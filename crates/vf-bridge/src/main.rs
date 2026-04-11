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
//!
//! ```text
//! ┌───────────┬──────────────────────────────┐
//! │ u32 BE    │ raw Ethernet frame (L2+)     │
//! │ (4 bytes) │ (length bytes, no padding)   │
//! └───────────┴──────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```sh
//! # Start BEFORE openshell-vm; libkrun connects on boot.
//! sudo vf-bridge --socket /run/vf-bridge/eth1.sock --ifname enp179s0f0v0
//!
//! # Then, in another terminal:
//! openshell-vm --protected-egress-socket /run/vf-bridge/eth1.sock ...
//! ```
//!
//! # Permissions
//!
//! `AF_PACKET` requires `CAP_NET_RAW`.  Run as root or grant the capability:
//! ```sh
//! sudo setcap cap_net_raw+ep ./target/release/vf-bridge
//! ```
//!
//! # Prototype status
//!
//! This is Phase 3 scaffolding — proven with TAP devices; VF-backed path on
//! BlueField representor requires hardware test (see STATUS.md).

#![allow(unsafe_code)] // AF_PACKET raw socket operations are inherently unsafe.

#[cfg(not(target_os = "linux"))]
compile_error!("vf-bridge requires Linux (AF_PACKET is not available on this platform)");

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

use clap::Parser;

// ── Constants ─────────────────────────────────────────────────────────────

/// `PACKET_IGNORE_OUTGOING` — suppress loopback of TX frames (Linux ≥ 4.20).
/// Prevents frames sent by this process from being re-received by the same
/// `AF_PACKET` socket, which would cause a forwarding loop.
const PACKET_IGNORE_OUTGOING: libc::c_int = 23;

/// Maximum Ethernet frame size accepted on either side (jumbo-frame safe).
const MAX_FRAME: usize = 9018;

// ── CLI ───────────────────────────────────────────────────────────────────

/// L2 bridge: libkrun/QEMU UNIX stream socket ↔ Linux netdev (AF_PACKET).
///
/// Start vf-bridge BEFORE openshell-vm. libkrun connects to the socket when
/// the VM boots and uses it as the backend for the guest eth1 virtio-net NIC.
#[derive(Parser)]
#[command(name = "vf-bridge", version)]
struct Cli {
    /// UNIX stream socket path. vf-bridge listens here; libkrun connects.
    /// The socket must not already exist (use the deploy script to remove
    /// stale sockets between runs).
    #[arg(long)]
    socket: PathBuf,

    /// Host Linux netdev to attach (e.g. enp179s0f0v0 for a BF3 VF, or
    /// tap0 for TAP-based testing).
    #[arg(long)]
    ifname: String,

    /// Print a log line for every relayed frame.
    #[arg(long)]
    verbose: bool,
}

// ── Counters ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct Counters {
    /// Frames forwarded from the guest to the host netdev.
    guest_to_host_frames: AtomicU64,
    guest_to_host_bytes: AtomicU64,
    guest_to_host_errors: AtomicU64,
    /// Frames forwarded from the host netdev to the guest.
    host_to_guest_frames: AtomicU64,
    host_to_guest_bytes: AtomicU64,
    host_to_guest_errors: AtomicU64,
}

// ── AF_PACKET helpers ─────────────────────────────────────────────────────

/// Open an `AF_PACKET SOCK_RAW` socket bound to `ifname`.
///
/// Sets `PACKET_IGNORE_OUTGOING` so that frames sent by this process are not
/// re-delivered to the same socket (prevents forwarding loops).
/// Sets `SO_RCVTIMEO` to 500 ms so that the receive loop can notice the
/// shutdown signal within half a second of the UNIX socket closing.
fn open_pkt_socket(ifname: &str) -> io::Result<OwnedFd> {
    // ETH_P_ALL in network byte order — receive all Ethernet frame types.
    #[allow(clippy::cast_possible_truncation)] // ETH_P_ALL = 0x0003, fits u16
    let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;

    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Safety: fd is a valid newly-created socket; we own it.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // Suppress TX loopback.
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
        // Non-fatal: kernel may pre-date 4.20 or the option may not apply.
        eprintln!(
            "warn: PACKET_IGNORE_OUTGOING not supported ({}); TX loopback possible",
            io::Error::last_os_error()
        );
    }

    // 500 ms receive timeout so Thread B can notice a shutdown signal.
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

    // Resolve interface index.
    let c_ifname = CString::new(ifname)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ifname contains NUL byte"))?;
    let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
    if ifindex == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface '{ifname}' not found"),
        ));
    }

    // Bind to the interface.
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)] // AF_PACKET fits u16
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

// ── QEMU framing ──────────────────────────────────────────────────────────

/// Read one QEMU-framed Ethernet packet from `reader`.
///
/// Format: `[u32 BE length][raw Ethernet frame]`.
/// Returns the number of bytes read into `buf`.
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

/// Write one QEMU-framed Ethernet packet to `writer`.
fn write_qemu_frame<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    #[allow(clippy::cast_possible_truncation)] // frame.len() <= MAX_FRAME < u32::MAX
    let len_bytes = (frame.len() as u32).to_be_bytes();
    writer.write_all(&len_bytes)?;
    writer.write_all(frame)?;
    Ok(())
}

// ── AF_PACKET I/O ─────────────────────────────────────────────────────────

/// Send a raw Ethernet frame to `fd` (AF_PACKET socket).
fn pkt_send(fd: libc::c_int, frame: &[u8]) -> io::Result<()> {
    let n = unsafe { libc::send(fd, frame.as_ptr().cast::<libc::c_void>(), frame.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive one raw Ethernet frame from `fd` (AF_PACKET socket).
/// Returns the number of bytes read, or an error (including `WouldBlock`
/// when the `SO_RCVTIMEO` fires).
fn pkt_recv(fd: libc::c_int, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)] // n >= 0 after the check above
    Ok(n as usize)
}

// ── Bridge threads ────────────────────────────────────────────────────────

/// Thread A — guest → host: read QEMU-framed packets from the UNIX socket,
/// write raw Ethernet frames to the `AF_PACKET` socket.
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
    // pkt_fd drops here, closing the AF_PACKET fd for this thread.
}

/// Thread B — host → guest: read raw Ethernet frames from the `AF_PACKET`
/// socket, write QEMU-framed packets to the UNIX socket.
///
/// Uses the `SO_RCVTIMEO` (500 ms) set in [`open_pkt_socket`] to wake up
/// periodically and check the shutdown flag.
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
                // SO_RCVTIMEO fired — check if Thread A has shut down.
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
    // pkt_fd drops here, closing the dup'd AF_PACKET fd for this thread.
}

// ── Entry point ───────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    // Open AF_PACKET socket first so we fail fast on permission errors.
    let pkt_fd = open_pkt_socket(&cli.ifname).unwrap_or_else(|e| {
        eprintln!("Error: AF_PACKET on '{}': {e}", cli.ifname);
        std::process::exit(1);
    });
    eprintln!(
        "vf-bridge: AF_PACKET bound to '{}' (fd {})",
        cli.ifname,
        pkt_fd.as_raw_fd()
    );

    // Listen for libkrun to connect.
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
    drop(listener); // No more connections expected.
    eprintln!("vf-bridge: libkrun connected — bridge active");

    // Clone UNIX stream: one handle per thread (full-duplex).
    let stream_read = stream;
    let stream_write = stream_read.try_clone().unwrap_or_else(|e| {
        eprintln!("Error: try_clone unix stream: {e}");
        std::process::exit(1);
    });

    // Duplicate the AF_PACKET fd: one per thread.
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

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{MAX_FRAME, read_qemu_frame, write_qemu_frame};

    /// Encode then decode a frame and verify round-trip integrity.
    #[test]
    fn qemu_frame_roundtrip() {
        let frame = b"\xff\xff\xff\xff\xff\xff\x52\x54\x00\xbf\x00\x01\x08\x00hello";
        let mut wire = Cursor::new(Vec::<u8>::new());
        write_qemu_frame(&mut wire, frame).unwrap();

        // Verify the length prefix on the wire.
        let wire_bytes = wire.into_inner();
        let encoded_len = u32::from_be_bytes(wire_bytes[..4].try_into().unwrap());
        assert_eq!(encoded_len as usize, frame.len());

        // Decode it back.
        let mut cursor = Cursor::new(wire_bytes);
        let mut buf = vec![0u8; MAX_FRAME];
        let n = read_qemu_frame(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, frame.len());
        assert_eq!(&buf[..n], frame);
    }

    /// A zero-length frame should be rejected (not valid Ethernet).
    #[test]
    fn qemu_frame_rejects_zero_length() {
        let wire: Vec<u8> = vec![0, 0, 0, 0]; // length = 0
        let mut cursor = Cursor::new(wire);
        let mut buf = vec![0u8; MAX_FRAME];
        assert!(read_qemu_frame(&mut cursor, &mut buf).is_err());
    }

    /// A frame exceeding MAX_FRAME should be rejected.
    #[test]
    fn qemu_frame_rejects_oversized() {
        let len: u32 = (MAX_FRAME + 1) as u32;
        let wire: Vec<u8> = len.to_be_bytes().to_vec();
        let mut cursor = Cursor::new(wire);
        let mut buf = vec![0u8; MAX_FRAME];
        assert!(read_qemu_frame(&mut cursor, &mut buf).is_err());
    }

    /// Multiple frames back-to-back on the same stream are decoded correctly.
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
