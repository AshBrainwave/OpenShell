// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `vf-bridge` — bidirectional L2 bridge between a libkrun/QEMU UNIX stream
//! socket and a Linux netdev via `AF_PACKET`.
//!
//! # Wire protocol (QEMU net-socket, stream mode)
//!
//! Each Ethernet frame on the UNIX socket is framed with a 4-byte big-endian
//! (network byte order) length prefix — the same format used by QEMU's
//! `-netdev socket,type=stream` backend, which libkrun speaks on Linux via
//! `krun_add_net_unixstream`.

#![allow(unsafe_code)] // AF_PACKET raw socket operations are inherently unsafe.

#[cfg(not(target_os = "linux"))]
compile_error!("vf-bridge requires Linux (AF_PACKET is not available on this platform)");

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

use clap::Parser;

const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
const MAX_FRAME: usize = 9018;

#[derive(Parser)]
#[command(name = "vf-bridge", version)]
struct Cli {
    /// UNIX stream socket path. vf-bridge listens here; libkrun connects.
    #[arg(long)]
    socket: PathBuf,

    /// Host Linux netdev to attach.
    #[arg(long)]
    ifname: String,

    /// Print a log line for every relayed frame.
    #[arg(long)]
    verbose: bool,
}

#[derive(Default)]
struct Counters {
    guest_to_host_frames: AtomicU64,
    guest_to_host_bytes: AtomicU64,
    guest_to_host_errors: AtomicU64,
    host_to_guest_frames: AtomicU64,
    host_to_guest_bytes: AtomicU64,
    host_to_guest_errors: AtomicU64,
}

fn open_pkt_socket(ifname: &str) -> io::Result<OwnedFd> {
    #[allow(clippy::cast_possible_truncation)]
    let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;

    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            owned.as_raw_fd(),
            libc::SOL_PACKET,
            PACKET_IGNORE_OUTGOING,
            std::ptr::addr_of!(one).cast::<libc::c_void>(),
            libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap(),
        )
    };
    if rc < 0 {
        eprintln!(
            "warn: PACKET_IGNORE_OUTGOING not supported ({}); TX loopback possible",
            io::Error::last_os_error()
        );
    }

    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 500_000,
    };
    unsafe {
        libc::setsockopt(
            owned.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(timeout).cast::<libc::c_void>(),
            libc::socklen_t::try_from(size_of::<libc::timeval>()).unwrap(),
        )
    };

    let c_ifname = CString::new(ifname)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ifname contains NUL byte"))?;
    let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
    if ifindex == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface '{ifname}' not found"),
        ));
    }

    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)]
    {
        addr.sll_family = libc::AF_PACKET as u16;
    }
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = i32::try_from(ifindex)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ifindex overflow"))?;

    let rc = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            libc::socklen_t::try_from(size_of::<libc::sockaddr_ll>()).unwrap(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(owned)
}

fn read_qemu_frame<R: Read>(reader: &mut R, buf: &mut Vec<u8>) -> io::Result<usize> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("QEMU frame length out of range: {len}"),
        ));
    }
    if buf.len() < len {
        buf.resize(len, 0);
    }
    reader.read_exact(&mut buf[..len])?;
    Ok(len)
}

fn write_qemu_frame<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    #[allow(clippy::cast_possible_truncation)]
    let len_bytes = (frame.len() as u32).to_be_bytes();
    writer.write_all(&len_bytes)?;
    writer.write_all(frame)?;
    Ok(())
}

fn pkt_send(fd: libc::c_int, frame: &[u8]) -> io::Result<()> {
    let n = unsafe { libc::send(fd, frame.as_ptr().cast::<libc::c_void>(), frame.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn pkt_recv(fd: libc::c_int, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)]
    Ok(n as usize)
}

fn guest_to_host(
    mut stream: UnixStream,
    pkt_fd: OwnedFd,
    shutdown: Arc<AtomicBool>,
    counters: Arc<Counters>,
    verbose: bool,
) {
    let raw = pkt_fd.as_raw_fd();
    let mut buf = vec![0u8; MAX_FRAME];
    loop {
        match read_qemu_frame(&mut stream, &mut buf) {
            Ok(n) => {
                counters
                    .guest_to_host_frames
                    .fetch_add(1, Ordering::Relaxed);
                #[allow(clippy::cast_possible_truncation)]
                counters
                    .guest_to_host_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
                if verbose {
                    eprintln!("[guest→host] {n} B");
                }
                if let Err(e) = pkt_send(raw, &buf[..n]) {
                    counters
                        .guest_to_host_errors
                        .fetch_add(1, Ordering::Relaxed);
                    eprintln!("guest→host pkt_send: {e}");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                eprintln!("guest→host: UNIX socket closed");
                break;
            }
            Err(e) => {
                eprintln!("guest→host read_qemu_frame: {e}");
                break;
            }
        }
    }
    shutdown.store(true, Ordering::Relaxed);
    eprintln!("guest→host thread done");
}

fn host_to_guest(
    pkt_fd: OwnedFd,
    mut stream: UnixStream,
    shutdown: Arc<AtomicBool>,
    counters: Arc<Counters>,
    verbose: bool,
) {
    let raw = pkt_fd.as_raw_fd();
    let mut buf = vec![0u8; MAX_FRAME];
    loop {
        match pkt_recv(raw, &mut buf) {
            Ok(0) => {}
            Ok(n) => {
                counters
                    .host_to_guest_frames
                    .fetch_add(1, Ordering::Relaxed);
                #[allow(clippy::cast_possible_truncation)]
                counters
                    .host_to_guest_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
                if verbose {
                    eprintln!("[host→guest] {n} B");
                }
                if let Err(e) = write_qemu_frame(&mut stream, &buf[..n]) {
                    counters
                        .host_to_guest_errors
                        .fetch_add(1, Ordering::Relaxed);
                    eprintln!("host→guest write_qemu_frame: {e}");
                    break;
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(libc::EAGAIN) =>
            {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(e) => {
                eprintln!("host→guest pkt_recv: {e}");
                break;
            }
        }
    }
    eprintln!("host→guest thread done");
}

fn main() {
    let cli = Cli::parse();

    let pkt_fd = open_pkt_socket(&cli.ifname).unwrap_or_else(|e| {
        eprintln!("Error: AF_PACKET on '{}': {e}", cli.ifname);
        std::process::exit(1);
    });
    eprintln!(
        "vf-bridge: AF_PACKET bound to '{}' (fd {})",
        cli.ifname,
        pkt_fd.as_raw_fd()
    );

    let listener = UnixListener::bind(&cli.socket).unwrap_or_else(|e| {
        eprintln!("Error: bind '{}': {e}", cli.socket.display());
        std::process::exit(1);
    });
    eprintln!(
        "vf-bridge: listening on '{}' — waiting for libkrun...",
        cli.socket.display()
    );

    let (stream, _peer) = listener.accept().unwrap_or_else(|e| {
        eprintln!("Error: accept: {e}");
        std::process::exit(1);
    });
    drop(listener);
    eprintln!("vf-bridge: libkrun connected — bridge active");

    let stream_read = stream;
    let stream_write = stream_read.try_clone().unwrap_or_else(|e| {
        eprintln!("Error: try_clone unix stream: {e}");
        std::process::exit(1);
    });

    let pkt_fd_b = pkt_fd.try_clone().unwrap_or_else(|e| {
        eprintln!("Error: try_clone pkt_fd: {e}");
        std::process::exit(1);
    });

    let counters = Arc::new(Counters::default());
    let shutdown = Arc::new(AtomicBool::new(false));

    let c1 = Arc::clone(&counters);
    let c2 = Arc::clone(&counters);
    let sd1 = Arc::clone(&shutdown);
    let sd2 = Arc::clone(&shutdown);
    let verbose = cli.verbose;

    let t_a = thread::Builder::new()
        .name("guest→host".into())
        .spawn(move || guest_to_host(stream_read, pkt_fd, sd1, c1, verbose))
        .expect("spawn guest→host thread");

    let t_b = thread::Builder::new()
        .name("host→guest".into())
        .spawn(move || host_to_guest(pkt_fd_b, stream_write, sd2, c2, verbose))
        .expect("spawn host→guest thread");

    let _ = t_a.join();
    let _ = t_b.join();

    print_counters(&counters);
}

fn print_counters(c: &Counters) {
    eprintln!("--- vf-bridge stats ---");
    eprintln!(
        "  guest→host: {} frames / {} B ({} errors)",
        c.guest_to_host_frames.load(Ordering::Relaxed),
        c.guest_to_host_bytes.load(Ordering::Relaxed),
        c.guest_to_host_errors.load(Ordering::Relaxed),
    );
    eprintln!(
        "  host→guest: {} frames / {} B ({} errors)",
        c.host_to_guest_frames.load(Ordering::Relaxed),
        c.host_to_guest_bytes.load(Ordering::Relaxed),
        c.host_to_guest_errors.load(Ordering::Relaxed),
    );
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{MAX_FRAME, read_qemu_frame, write_qemu_frame};

    #[test]
    fn qemu_frame_roundtrip() {
        let frame = b"\xff\xff\xff\xff\xff\xff\x52\x54\x00\xbf\x00\x01\x08\x00hello";
        let mut wire = Cursor::new(Vec::<u8>::new());
        write_qemu_frame(&mut wire, frame).unwrap();

        let wire_bytes = wire.into_inner();
        let encoded_len = u32::from_be_bytes(wire_bytes[..4].try_into().unwrap());
        assert_eq!(encoded_len as usize, frame.len());

        let mut cursor = Cursor::new(wire_bytes);
        let mut buf = vec![0u8; MAX_FRAME];
        let n = read_qemu_frame(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, frame.len());
        assert_eq!(&buf[..n], frame);
    }

    #[test]
    fn qemu_frame_rejects_zero_length() {
        let wire: Vec<u8> = vec![0, 0, 0, 0];
        let mut cursor = Cursor::new(wire);
        let mut buf = vec![0u8; MAX_FRAME];
        assert!(read_qemu_frame(&mut cursor, &mut buf).is_err());
    }

    #[test]
    fn qemu_frame_rejects_oversized() {
        let len: u32 = (MAX_FRAME + 1) as u32;
        let wire: Vec<u8> = len.to_be_bytes().to_vec();
        let mut cursor = Cursor::new(wire);
        let mut buf = vec![0u8; MAX_FRAME];
        assert!(read_qemu_frame(&mut cursor, &mut buf).is_err());
    }

    #[test]
    fn qemu_frame_multiple_frames() {
        let frames: &[&[u8]] = &[b"frame-one-data", b"frame-two"];
        let mut wire = Cursor::new(Vec::<u8>::new());
        for frame in frames {
            write_qemu_frame(&mut wire, frame).unwrap();
        }
        let mut cursor = Cursor::new(wire.into_inner());
        let mut buf = vec![0u8; MAX_FRAME];
        for expected in frames {
            let n = read_qemu_frame(&mut cursor, &mut buf).unwrap();
            assert_eq!(&buf[..n], *expected);
        }
    }
}
