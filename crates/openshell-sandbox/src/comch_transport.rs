// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! DPU side of the OpenShell Comm Channel Proxy Protocol (OCPP).
//!
//! Replaces the TCP listener in `openshell-dpu-proxy` with a DOCA Comm Channel
//! server endpoint.  The existing proxy logic (OPA, TLS MITM, credential
//! injection) is unchanged — it sees a `TunnelStream` that implements
//! `AsyncRead + AsyncWrite`, identical to a `TcpStream`.
//!
//! # Architecture
//!
//! ```text
//! DOCA Comm Channel (PCIe)
//!        │
//!        ▼
//! ComchListener::accept()  ←──  OPEN msg from host shim
//!        │                       OPA check on (host, port)
//!        │  allow?
//!        ▼
//! TunnelStream (AsyncRead + AsyncWrite)
//!        │
//!        ▼
//! existing proxy logic (TLS MITM, credential injection, upstream relay)
//! ```
//!
//! # DOCA integration
//!
//! DOCA Comm Channel is a C library.  This module links against the
//! `doca_cc_server.c` wrapper (compiled via `build.rs`) which exposes a simple
//! callback-based C API.  The Rust code calls into that wrapper via FFI.

use std::collections::HashMap;
use std::ffi::CString;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};

// ── protocol constants ────────────────────────────────────────────────────

const HEADER_LEN: usize = 5;
const MAX_PAYLOAD: usize = 4091; // 4096 - HEADER_LEN
const INITIAL_CREDITS: u16 = 16;
const CREDIT_REPLENISH_AT: u16 = 8;

// ── message types ─────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum MsgType {
    Open = 0x01,
    OpenOk = 0x02,
    OpenErr = 0x03,
    Data = 0x04,
    Fin = 0x05,
    Rst = 0x06,
    Credit = 0x07,
    Ping = 0x08,
    Pong = 0x09,
}

impl MsgType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Open),
            0x02 => Some(Self::OpenOk),
            0x03 => Some(Self::OpenErr),
            0x04 => Some(Self::Data),
            0x05 => Some(Self::Fin),
            0x06 => Some(Self::Rst),
            0x07 => Some(Self::Credit),
            0x08 => Some(Self::Ping),
            0x09 => Some(Self::Pong),
            _ => None,
        }
    }
}

// ── wire encoding ─────────────────────────────────────────────────────────

fn encode(msg_type: MsgType, tunnel_id: u16, payload: &[u8]) -> Bytes {
    let plen = payload.len() as u16;
    let mut buf = BytesMut::with_capacity(HEADER_LEN + payload.len());
    buf.extend_from_slice(&[
        msg_type as u8,
        (tunnel_id >> 8) as u8,
        (tunnel_id & 0xff) as u8,
        (plen >> 8) as u8,
        (plen & 0xff) as u8,
    ]);
    buf.extend_from_slice(payload);
    buf.freeze()
}

fn decode_header(buf: &[u8]) -> Option<(MsgType, u16, u16)> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let msg_type = MsgType::from_u8(buf[0])?;
    let tunnel_id = ((buf[1] as u16) << 8) | buf[2] as u16;
    let plen = ((buf[3] as u16) << 8) | buf[4] as u16;
    Some((msg_type, tunnel_id, plen))
}

// ── inbound message ───────────────────────────────────────────────────────

#[derive(Debug)]
enum InboundMsg {
    /// Bytes arriving for a tunnel (DATA)
    Data { bytes: Bytes },
    /// Remote half-close (FIN)
    Fin,
    /// Abrupt close (RST)
    Rst { reason: String },
    /// Flow control credits granted by host
    Credit { credits: u16 },
}

// ── TunnelStream ──────────────────────────────────────────────────────────
//
// Presented to the existing proxy logic.  Behaves like a TcpStream.

pub struct TunnelStream {
    tunnel_id: u16,
    /// Bytes received from host, buffered here for AsyncRead.
    rx_buf: BytesMut,
    /// Channel on which the Comch dispatcher delivers InboundMsg.
    rx: mpsc::Receiver<InboundMsg>,
    /// Channel to send outbound bytes (DATA/FIN) back to host.
    tx: Arc<ComchSender>,
    /// Credits we hold to send DATA to host.
    send_credits: u16,
    /// Credits consumed since last CREDIT grant to host.
    recv_consumed: u16,
    /// True when host sent FIN.
    remote_fin: bool,
}

impl TunnelStream {
    fn new(tunnel_id: u16, rx: mpsc::Receiver<InboundMsg>, tx: Arc<ComchSender>) -> Self {
        Self {
            tunnel_id,
            rx_buf: BytesMut::new(),
            rx,
            tx,
            send_credits: INITIAL_CREDITS,
            recv_consumed: 0,
            remote_fin: false,
        }
    }

    fn send_data_frame(&self, data: &[u8]) {
        let msg = encode(MsgType::Data, self.tunnel_id, data);
        self.tx.send(msg);
    }

    fn send_fin(&self) {
        let msg = encode(MsgType::Fin, self.tunnel_id, &[]);
        self.tx.send(msg);
    }

    fn send_credit_grant(&self, credits: u16) {
        let payload = [(credits >> 8) as u8, (credits & 0xff) as u8];
        let msg = encode(MsgType::Credit, self.tunnel_id, &payload);
        self.tx.send(msg);
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Drain any already-buffered bytes first.
        if !self.rx_buf.is_empty() {
            let n = buf.remaining().min(self.rx_buf.len());
            buf.put_slice(&self.rx_buf.split_to(n));
            return Poll::Ready(Ok(()));
        }

        if self.remote_fin {
            return Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(())), // channel closed = EOF
            Poll::Ready(Some(msg)) => match msg {
                InboundMsg::Data { bytes } => {
                    self.recv_consumed += 1;
                    if self.recv_consumed >= CREDIT_REPLENISH_AT {
                        self.send_credit_grant(self.recv_consumed);
                        self.recv_consumed = 0;
                    }
                    let n = buf.remaining().min(bytes.len());
                    buf.put_slice(&bytes[..n]);
                    if n < bytes.len() {
                        self.rx_buf.extend_from_slice(&bytes[n..]);
                    }
                    Poll::Ready(Ok(()))
                }
                InboundMsg::Fin => {
                    self.remote_fin = true;
                    Poll::Ready(Ok(()))
                }
                InboundMsg::Rst { reason } => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    reason,
                ))),
                InboundMsg::Credit { credits } => {
                    self.send_credits += credits;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            },
        }
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.send_credits == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let chunk = &buf[..buf.len().min(MAX_PAYLOAD)];
        self.send_credits -= 1;
        self.send_data_frame(chunk);
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.send_fin();
        Poll::Ready(Ok(()))
    }
}

// ── FFI declarations ──────────────────────────────────────────────────────
//
// These match the C API in doca_cc_server.h.
// The actual linking is done via build.rs.

#[allow(non_camel_case_types)]
type cc_server_t = std::ffi::c_void;

/// Signature for the message-received callback passed to cc_server_create.
type CcMsgCb = unsafe extern "C" fn(
    conn_id: u64,
    buf: *const u8,
    len: u32,
    userdata: *mut std::ffi::c_void,
);

/// Signature for the connected/disconnected callbacks.
type CcConnCb = unsafe extern "C" fn(conn_id: u64, userdata: *mut std::ffi::c_void);

#[link(name = "doca_cc_server")]
unsafe extern "C" {
    fn cc_server_create(
        pci_addr: *const std::ffi::c_char,
        rep_pci_addr: *const std::ffi::c_char,
        service_name: *const std::ffi::c_char,
        msg_cb: CcMsgCb,
        conn_cb: CcConnCb,
        disconn_cb: CcConnCb,
        userdata: *mut std::ffi::c_void,
    ) -> *mut cc_server_t;

    fn cc_server_send(
        s: *mut cc_server_t,
        conn_id: u64,
        buf: *const u8,
        len: u32,
    ) -> std::ffi::c_int;

    fn cc_server_run(s: *mut cc_server_t);
    fn cc_server_stop(s: *mut cc_server_t);
    fn cc_server_destroy(s: *mut cc_server_t);
}

// ── ComchSender ───────────────────────────────────────────────────────────
//
// Shared outbound queue. The DOCA progress engine thread drains it and
// submits cc_server_send calls.

pub struct ComchSender {
    raw_server: *mut cc_server_t,
    // conn_id of the current active connection (0 means none)
    conn_id: std::sync::atomic::AtomicU64,
    // Fallback queue for frames enqueued before the host connects
    queue: std::sync::Mutex<Vec<Bytes>>,
}

// SAFETY: The raw pointer is to a C object whose lifetime is managed by
// cc_server_t. We guarantee cc_server_destroy() is called only after all
// ComchSender clones are dropped (via Arc).
unsafe impl Send for ComchSender {}
unsafe impl Sync for ComchSender {}

impl ComchSender {
    fn new(raw_server: *mut cc_server_t) -> Self {
        Self {
            raw_server,
            conn_id: std::sync::atomic::AtomicU64::new(0),
            queue: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn set_conn_id(&self, id: u64) {
        self.conn_id
            .store(id, std::sync::atomic::Ordering::Release);
        // Flush any queued frames that arrived before the connection.
        let pending: Vec<Bytes> = {
            let mut q = self.queue.lock().unwrap();
            std::mem::take(&mut *q)
        };
        for msg in pending {
            self.send_immediate(id, &msg);
        }
    }

    fn clear_conn_id(&self) {
        self.conn_id
            .store(0, std::sync::atomic::Ordering::Release);
    }

    fn send_immediate(&self, conn_id: u64, msg: &Bytes) {
        unsafe {
            cc_server_send(self.raw_server, conn_id, msg.as_ptr(), msg.len() as u32);
        }
    }

    fn send(&self, msg: Bytes) {
        let id = self.conn_id.load(std::sync::atomic::Ordering::Acquire);
        if id != 0 {
            self.send_immediate(id, &msg);
        } else {
            // No connection yet — queue for later delivery
            self.queue.lock().unwrap().push(msg);
        }
    }
}

// ── Shared listener state ─────────────────────────────────────────────────
//
// Passed into the C callbacks as a raw pointer (through cc_server_create's
// userdata). Wrapped in Arc<Mutex<...>> so the Tokio dispatcher task and the
// C poll-thread can share it.

struct ListenerState {
    /// Channel to deliver raw OCPP frames from the C thread to the Tokio dispatcher.
    raw_tx: mpsc::Sender<(u64, Vec<u8>)>,
    /// Notified on connect / disconnect events.
    connected_tx: mpsc::Sender<u64>,
    disconnected_tx: mpsc::Sender<u64>,
}

// ── C callback trampolines ────────────────────────────────────────────────

unsafe extern "C" fn trampoline_msg(
    conn_id: u64,
    buf: *const u8,
    len: u32,
    userdata: *mut std::ffi::c_void,
) {
    let state = &*(userdata as *const ListenerState);
    let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    let data = slice.to_vec();
    // best-effort; if the channel is full we drop the frame
    let _ = state.raw_tx.try_send((conn_id, data));
}

unsafe extern "C" fn trampoline_connected(
    conn_id: u64,
    userdata: *mut std::ffi::c_void,
) {
    let state = &*(userdata as *const ListenerState);
    let _ = state.connected_tx.try_send(conn_id);
}

unsafe extern "C" fn trampoline_disconnected(
    conn_id: u64,
    userdata: *mut std::ffi::c_void,
) {
    let state = &*(userdata as *const ListenerState);
    let _ = state.disconnected_tx.try_send(conn_id);
}

// ── ComchListener ─────────────────────────────────────────────────────────

pub struct ComchListener {
    /// Incoming accepted TunnelStreams (after OPA allows).
    accepted_rx: mpsc::Receiver<(TunnelStream, String, u16)>,
    /// Raw server pointer — kept alive for Drop.
    raw_server: *mut cc_server_t,
    /// Sender — kept alive so ComchSender stays valid.
    _sender: Arc<ComchSender>,
    /// ListenerState — kept alive so C callbacks can dereference userdata.
    _state: Box<ListenerState>,
}

// SAFETY: raw_server is only touched by cc_server_stop/destroy in Drop.
unsafe impl Send for ComchListener {}

impl ComchListener {
    /// Start the Comm Channel server and return a listener.
    ///
    /// Spawns:
    ///  1. A blocking thread running the DOCA progress engine (`cc_server_run`).
    ///  2. A Tokio task that processes inbound OCPP messages via OPA.
    pub fn start(
        pci_addr: &str,
        rep_pci_addr: &str,
        service_name: &str,
        opa_engine: Arc<crate::opa::OpaEngine>,
    ) -> Result<Self, String> {
        let (accepted_tx, accepted_rx) = mpsc::channel(64);
        let (raw_tx, mut raw_rx) = mpsc::channel::<(u64, Vec<u8>)>(256);
        let (connected_tx, mut connected_rx) = mpsc::channel::<u64>(8);
        let (disconnected_tx, mut disconnected_rx) = mpsc::channel::<u64>(8);

        // Heap-allocate the state so we can pass a stable pointer to C.
        let state = Box::new(ListenerState {
            raw_tx,
            connected_tx,
            disconnected_tx,
        });
        let state_ptr = state.as_ref() as *const ListenerState as *mut std::ffi::c_void;

        let pci_c =
            CString::new(pci_addr).map_err(|e| format!("invalid pci_addr: {e}"))?;
        let rep_c =
            CString::new(rep_pci_addr).map_err(|e| format!("invalid rep_pci_addr: {e}"))?;
        let svc_c =
            CString::new(service_name).map_err(|e| format!("invalid service_name: {e}"))?;

        let raw_server = unsafe {
            cc_server_create(
                pci_c.as_ptr(),
                rep_c.as_ptr(),
                svc_c.as_ptr(),
                trampoline_msg,
                trampoline_connected,
                trampoline_disconnected,
                state_ptr,
            )
        };

        if raw_server.is_null() {
            return Err(format!(
                "cc_server_create failed for device {pci_addr} rep {rep_pci_addr} service {service_name}"
            ));
        }

        let sender = Arc::new(ComchSender::new(raw_server));
        let sender2 = sender.clone();
        let tx_for_dispatcher = sender.clone();

        // Per-tunnel dispatch: tunnel_id → mpsc::Sender<InboundMsg>
        let tunnels: Arc<Mutex<HashMap<u16, mpsc::Sender<InboundMsg>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let tunnels2 = tunnels.clone();

        // Blocking thread: DOCA progress engine
        let raw_for_thread = raw_server as usize; // usize is Send
        std::thread::spawn(move || {
            let ptr = raw_for_thread as *mut cc_server_t;
            unsafe { cc_server_run(ptr) };
        });

        // Tokio task: dispatch connection events and OCPP frames
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Host connected
                    Some(conn_id) = connected_rx.recv() => {
                        tracing::info!(conn_id = %format!("0x{conn_id:016x}"), "Host connected via Comm Channel");
                        sender2.set_conn_id(conn_id);
                    }
                    // Host disconnected
                    Some(conn_id) = disconnected_rx.recv() => {
                        tracing::info!(conn_id = %format!("0x{conn_id:016x}"), "Host disconnected from Comm Channel");
                        sender2.clear_conn_id();
                        // RST all open tunnels
                        let mut tmap = tunnels2.lock().await;
                        for (_, t_tx) in tmap.drain() {
                            let _ = t_tx.send(InboundMsg::Rst {
                                reason: "Comm Channel connection closed".to_string(),
                            }).await;
                        }
                    }
                    // Inbound OCPP frame
                    Some((conn_id, raw)) = raw_rx.recv() => {
                        if raw.len() < HEADER_LEN { continue; }
                        let Some((msg_type, tid, plen)) = decode_header(&raw) else { continue };
                        let end = HEADER_LEN + plen as usize;
                        if raw.len() < end { continue; }
                        let payload = &raw[HEADER_LEN..end];

                        match msg_type {
                            MsgType::Open => {
                                // payload: host_credits(2) port(2) host(N)
                                if payload.len() < 4 { continue; }
                                let _host_credits = ((payload[0] as u16) << 8) | payload[1] as u16;
                                let port = ((payload[2] as u16) << 8) | payload[3] as u16;
                                let host = String::from_utf8_lossy(&payload[4..]).to_string();

                                let opa = opa_engine.clone();
                                let tx_clone = tx_for_dispatcher.clone();
                                let tunnels_clone = tunnels2.clone();
                                let accepted_tx2 = accepted_tx.clone();
                                let cid = conn_id;

                                tokio::spawn(async move {
                                    let input = crate::opa::NetworkInput {
                                        host: host.clone(),
                                        port,
                                        binary_path: std::path::PathBuf::new(),
                                        binary_sha256: String::new(),
                                        ancestors: vec![],
                                        cmdline_paths: vec![],
                                    };
                                    let allowed = tokio::task::spawn_blocking({
                                        let opa = opa.clone();
                                        let input = input;
                                        move || opa.evaluate_network_action(&input)
                                    })
                                    .await;

                                    match allowed {
                                        Ok(Ok(crate::opa::NetworkAction::Allow { .. })) => {
                                            let credits_be = INITIAL_CREDITS.to_be_bytes();
                                            let ok_msg = encode(MsgType::OpenOk, tid, &credits_be);
                                            tx_clone.send(ok_msg);

                                            let (inbound_tx, inbound_rx) = mpsc::channel(64);
                                            tunnels_clone.lock().await.insert(tid, inbound_tx);
                                            let stream = TunnelStream::new(tid, inbound_rx, tx_clone);
                                            let _ = accepted_tx2.send((stream, host, port)).await;
                                        }
                                        _ => {
                                            tracing::warn!(host = %host, port, tunnel_id = tid, "OPA denied connection");
                                            let reason = "denied by OPA policy";
                                            let err_msg =
                                                encode(MsgType::OpenErr, tid, reason.as_bytes());
                                            tx_clone.send(err_msg);
                                        }
                                    }
                                    let _ = cid; // suppress unused warning
                                });
                            }

                            MsgType::Data | MsgType::Fin | MsgType::Rst | MsgType::Credit => {
                                let tunnels_guard = tunnels2.lock().await;
                                if let Some(t_tx) = tunnels_guard.get(&tid) {
                                    let msg = match msg_type {
                                        MsgType::Data => Some(InboundMsg::Data {
                                            bytes: Bytes::copy_from_slice(payload),
                                        }),
                                        MsgType::Fin => Some(InboundMsg::Fin),
                                        MsgType::Rst => Some(InboundMsg::Rst {
                                            reason: String::from_utf8_lossy(payload).to_string(),
                                        }),
                                        MsgType::Credit => {
                                            let c = if payload.len() >= 2 {
                                                ((payload[0] as u16) << 8) | payload[1] as u16
                                            } else {
                                                0
                                            };
                                            Some(InboundMsg::Credit { credits: c })
                                        }
                                        _ => None,
                                    };
                                    if let Some(m) = msg {
                                        let _ = t_tx.send(m).await;
                                    }
                                } else {
                                    // Unknown tunnel — send RST back
                                    let rst = encode(MsgType::Rst, tid, b"unknown tunnel");
                                    tx_for_dispatcher.send(rst);
                                }
                                drop(tunnels_guard); // explicit drop to satisfy borrow checker
                            }

                            MsgType::Ping => {
                                let pong = encode(MsgType::Pong, 0, &[]);
                                tx_for_dispatcher.send(pong);
                            }

                            _ => {}
                        }
                    }
                    else => break,
                }
            }
        });

        Ok(Self {
            accepted_rx,
            raw_server,
            _sender: sender,
            _state: state,
        })
    }

    /// Accept the next tunnel.  Returns (stream, host, port) just like
    /// a TcpListener would return (stream, peer_addr).
    pub async fn accept(&mut self) -> Option<(TunnelStream, String, u16)> {
        self.accepted_rx.recv().await
    }
}

impl Drop for ComchListener {
    fn drop(&mut self) {
        unsafe {
            cc_server_stop(self.raw_server);
            cc_server_destroy(self.raw_server);
        }
    }
}
