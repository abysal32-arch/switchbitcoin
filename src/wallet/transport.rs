//! Real peer transport — blocking TCP with u32-BE length framing (Task 04).
//!
//! SECURITY: this is PLAINTEXT TCP for pre-alpha LAN/regtest interop ONLY.
//! No authentication, no encryption, no metadata protection — it must NOT
//! carry a swap involving real funds. The production channel (Tor + Noise-
//! style encryption over the authenticated discovery layer) is post-pre-alpha
//! work; this module exists so two wallets on one machine / LAN segment can
//! run the adaptor exchange over an actual socket instead of an in-process
//! channel. The protocol itself stays safe over a hostile transport — every
//! received frame still passes `wire::open_message` inside `PeerSession`
//! (version + exact-length + session-id envelope gate, Task 05), and any
//! transport failure maps to `Error::Abort`, which the drivers route to the
//! refund path (forward-or-refund holds).
//!
//! Framing: each message is `u32 big-endian payload length ++ payload`.
//! `recv` returns exactly one whole frame; partial reads are looped. Frames
//! above [`MAX_FRAME`] are rejected on BOTH sides (`Error::Validation`)
//! before any payload allocation, so a malicious header cannot drive an
//! unbounded allocation.
//!
//! Timeout discipline: the configured I/O timeout is a WHOLE-FRAME deadline,
//! not a per-syscall one. A peer dripping one byte per read would otherwise
//! restart a per-syscall clock forever; here the deadline is fixed when the
//! frame starts and every partial read/write is re-armed against the time
//! REMAINING, so `send`/`recv` return `Error::Abort` no later than the
//! deadline regardless of how the peer paces bytes.
//!
//! Failure semantics: every I/O error is TERMINAL for the connection — after
//! any `Err` the stream may be mid-frame (desynchronized) and must not be
//! reused. That matches the state machine's abort discipline: a transport
//! error aborts the session and a retry is a brand-new session. The one
//! exception is the local oversize-send rejection, which writes nothing.
//!
//! Dial resilience (Task 24): a fresh CONNECT — before any rendezvous or
//! negotiate frame — leases and persists nothing, so
//! [`TcpTransport::connect_retrying`] retries a TRANSIENT connect failure
//! (refused / timed out / unreachable) a bounded number of times with a fixed
//! short backoff; the maker's listener often is not up the instant the taker
//! dials. The retry is confined to the dial: once a stream is established it is
//! handed to the caller and NEVER re-dialed, so a later rendezvous/negotiate
//! failure follows the normal abort rules (INV-2: a broken session is
//! non-resumable). The `runner` module docs pin exactly where this
//! "free-failure zone" ends (the pre-encumbrance lease).
//!
//! Timeout ladder (Task 24 — single-sourced HERE so `swap` and `serve` cannot
//! drift; each rung says why):
//!   * connect: the OS default per attempt, wrapped by the bounded dial retry
//!     above ([`DEFAULT_CONNECT_RETRIES`] × [`DIAL_RETRY_BACKOFF`]).
//!   * rendezvous leash [`RENDEZVOUS_LEASH`] (10 s): a ticket adds exactly one
//!     nonce TAKE/ECHO round-trip above `negotiate_swap`; the short leash keeps
//!     a silent dialer/maker from hanging the accept/dial loop.
//!   * negotiation + in-run I/O [`negotiation_io_timeout`] (`max(120 s, 3×poll)`):
//!     the whole-frame deadline for the hello/offer handshake and every in-run
//!     frame. The floor keeps a healthy interactive exchange alive; scaling with
//!     the poll cadence covers the Phase-A rendezvous skew (bounded by the
//!     SLOWER side's poll) — a fixed budget under a large `--poll-secs` would
//!     abort healthy FUNDED swaps into their safe-but-slow refund path.
//!   * accept windows: the maker's `--make`/`--listen` wait
//!     ([`accept_timeout`](Self::accept_timeout), default 600 s) and serve's
//!     ~900 ms non-blocking accept slices — bound how long a listener waits on a
//!     peer that may never arrive.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::settlement::state_machine::Transport;
use crate::{Error, Result};

/// Hard ceiling on a single frame's PAYLOAD size (1 MiB). The largest
/// protocol message is a pre-armed refund carrying a fully signed tx
/// (standardness caps those around 400 KB); 1 MiB clears that with margin
/// while keeping the worst-case allocation a peer can force trivially small.
pub const MAX_FRAME: u32 = 1_048_576;

/// Default whole-frame send/recv deadline. The adaptor exchange is
/// interactive — the counterparty computes for milliseconds between
/// messages — so a peer that cannot deliver a frame within this window is
/// dead or stalling, and surfacing `Error::Abort` hands the swap to the
/// refund path instead of hanging a driver forever.
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Floor for re-armed socket timeouts: a deadline sliver below 1 ms still
/// gets a real (nonzero) socket timeout rather than tripping std's
/// zero-duration rejection.
const MIN_REARM: Duration = Duration::from_millis(1);

/// Fixed pause between dial retries ([`TcpTransport::connect_retrying`]). Short
/// on purpose: the dominant retry case is "the maker bound its port a moment
/// after the taker dialed", which clears in seconds — a long backoff would only
/// delay a healthy connect. Kept separate from the retry COUNT (a flag) so an
/// operator tunes HOW MANY times we redial, not how patiently.
pub const DIAL_RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// Default number of ADDITIONAL dial attempts after the first (5 total by
/// default). Small and bounded — enough to ride out a listener that is a few
/// seconds late, never so many that an unreachable peer stalls a command for
/// minutes. The binary exposes this as `--connect-retries`.
pub const DEFAULT_CONNECT_RETRIES: u32 = 4;

/// The rendezvous nonce round-trip leash. A ticket adds exactly one TAKE/ECHO
/// exchange above `negotiate_swap`, and it must not let a silent peer hang the
/// accept/dial loop. Applied by both `swap` and `serve` around the rendezvous,
/// then replaced by [`negotiation_io_timeout`] for the negotiation proper.
pub const RENDEZVOUS_LEASH: Duration = Duration::from_secs(10);

/// The whole-frame I/O deadline for the negotiation handshake AND the in-run
/// exchange: `max(120 s, 3×poll)`. Single-sourced (Task 24) so the one-shot
/// `swap` command and the `serve` worker cannot drift. The 120 s floor keeps a
/// healthy interactive exchange from timing out; scaling with `poll` covers the
/// Phase-A rendezvous skew, which is bounded by the SLOWER side's poll cadence —
/// a fixed budget under a large `--poll-secs` would abort healthy FUNDED swaps
/// into their (safe but slow) refund path.
pub fn negotiation_io_timeout(poll: Duration) -> Duration {
    Duration::from_secs(120).max(poll.saturating_mul(3))
}

/// Whether a CONNECT-phase I/O failure is transient enough to retry: only the
/// "peer/route not ready yet" classes. A permanent error (an unresolvable or
/// malformed address ⇒ `InvalidInput`, or any other kind) fails fast — no
/// amount of redialing will fix it, and the caller gets the clean error now.
fn is_transient_connect_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::TimedOut
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::WouldBlock
    )
}

/// The dial retry loop, generic over the dial op so the RETRY POLICY (bounded
/// count, transient-only, backoff between attempts) is unit-testable with
/// injected `io::Result`s — no real sockets, no platform-specific connect
/// timing. Retries a transient failure up to `retries` times, sleeping
/// `backoff` between attempts and emitting one `log` line per retry; returns
/// the first `Ok`, or the LAST failure on give-up.
fn dial_with_retry<T, F>(
    retries: u32,
    backoff: Duration,
    log: &mut dyn FnMut(String),
    mut dial: F,
) -> std::io::Result<T>
where
    F: FnMut() -> std::io::Result<T>,
{
    let mut attempt: u32 = 0;
    loop {
        match dial() {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt >= retries || !is_transient_connect_error(&e) {
                    return Err(e);
                }
                attempt += 1;
                log(format!(
                    "connect failed ({e}); retry {attempt}/{retries} in {}s",
                    backoff.as_secs()
                ));
                std::thread::sleep(backoff);
            }
        }
    }
}

/// Map an I/O failure into the settlement error classes the drivers already
/// handle. Everything is `Abort` (route to refund); the message distinguishes
/// the operationally different cases for logs.
fn map_io(e: std::io::Error) -> Error {
    use std::io::ErrorKind;
    match e.kind() {
        // Read/write timeout: Windows reports TimedOut, Unix WouldBlock.
        ErrorKind::TimedOut | ErrorKind::WouldBlock => Error::Abort("peer i/o timed out"),
        ErrorKind::UnexpectedEof
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe => Error::Abort("peer hung up"),
        _ => Error::Abort("peer connection failed"),
    }
}

/// Blocking, length-framed TCP implementation of [`Transport`].
#[derive(Debug)]
pub struct TcpTransport {
    stream: TcpStream,
    /// Whole-frame deadline budget; `None` = block indefinitely.
    io_timeout: Option<Duration>,
}

impl TcpTransport {
    /// Connect to a listening peer. Send/recv deadlines default to
    /// [`DEFAULT_IO_TIMEOUT`]; the connect itself uses the OS default.
    pub fn connect(addr: impl ToSocketAddrs) -> Result<Self> {
        let stream = TcpStream::connect(addr).map_err(map_io)?;
        Self::from_stream(stream)
    }

    /// Connect with an explicit connect-phase timeout (for callers that must
    /// not block on an unreachable peer even for the OS default).
    pub fn connect_timeout(addr: &SocketAddr, timeout: Duration) -> Result<Self> {
        let stream = TcpStream::connect_timeout(addr, timeout).map_err(map_io)?;
        Self::from_stream(stream)
    }

    /// Dial `addr`, retrying a TRANSIENT connect failure up to `retries` extra
    /// times (total attempts = `retries + 1`) with a fixed `backoff` between
    /// attempts; `log` reports each retry so a waiting tester sees progress
    /// instead of a silent stall.
    ///
    /// Only transient failures (see [`is_transient_connect_error`]) retry — a
    /// permanent error (an unresolvable/malformed address) fails on the first
    /// attempt. On give-up the LAST failure is returned via [`map_io`],
    /// byte-identical to a single-shot [`connect`](Self::connect), so the
    /// caller's message discipline is unchanged.
    ///
    /// SAFETY: every attempt runs strictly BEFORE the rendezvous+`negotiate_swap`
    /// lease boundary (see the `runner` module's "free-failure zone") — a redial
    /// leases nothing and persists nothing, so bounded re-dialing is free. NEVER
    /// use this to reconnect a link that has already carried a rendezvous or a
    /// negotiate frame: INV-2 makes a broken signing session non-resumable, and
    /// a retry is a FRESH swap, never a resumed one.
    pub fn connect_retrying(
        addr: &str,
        retries: u32,
        backoff: Duration,
        log: &mut dyn FnMut(String),
    ) -> Result<Self> {
        // Prefix the addr onto the retry-progress lines; the loop itself is
        // address-agnostic (and unit-tested with an injected dial op below).
        let stream = dial_with_retry(retries, backoff, &mut |m| log(format!("{addr}: {m}")), || {
            TcpStream::connect(addr)
        })
        .map_err(map_io)?;
        Self::from_stream(stream)
    }

    /// Accept one inbound connection from an already-bound listener.
    /// NOTE: blocks until a peer connects — the caller owns that wait. Use
    /// [`Self::accept_timeout`] when the wait itself must be bounded.
    pub fn accept(listener: &TcpListener) -> Result<Self> {
        let (stream, _peer) = listener.accept().map_err(map_io)?;
        Self::from_stream(stream)
    }

    /// Accept one inbound connection, waiting at most `timeout`. Expiry
    /// surfaces `Error::Abort` so a listen-side driver can give up cleanly
    /// instead of hanging on a peer that never arrives. The listener is
    /// restored to blocking mode before returning.
    pub fn accept_timeout(listener: &TcpListener, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::Validation("zero accept timeout"));
        }
        listener.set_nonblocking(true).map_err(map_io)?;
        let deadline = Instant::now() + timeout;
        let outcome = loop {
            match listener.accept() {
                Ok((stream, _peer)) => break Ok(stream),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break Err(Error::Abort("no inbound peer before deadline"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => break Err(map_io(e)),
            }
        };
        let _ = listener.set_nonblocking(false);
        let stream = outcome?;
        // Some platforms hand the accepted socket the listener's nonblocking
        // flag; force blocking before applying the transport discipline.
        stream.set_nonblocking(false).map_err(map_io)?;
        Self::from_stream(stream)
    }

    /// Wrap an already-connected stream, applying the transport's socket
    /// discipline: TCP_NODELAY (the exchange is small request/response
    /// messages; Nagle only adds latency) and the default frame deadline.
    pub fn from_stream(stream: TcpStream) -> Result<Self> {
        stream.set_nodelay(true).map_err(map_io)?;
        let mut t = TcpTransport { stream, io_timeout: None };
        t.set_io_timeout(Some(DEFAULT_IO_TIMEOUT))?;
        Ok(t)
    }

    /// Override the whole-frame deadline. `None` blocks indefinitely (tests /
    /// supervised runs only — a driver should always keep a finite timeout so
    /// a dead peer becomes an abort, not a hang).
    pub fn set_io_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        if timeout == Some(Duration::ZERO) {
            // std rejects a zero Duration; catch it as a config error here.
            return Err(Error::Validation("zero i/o timeout (use None for blocking)"));
        }
        // Keep the socket timeouts in sync so the `None` (fully blocking)
        // mode really blocks: per-frame re-arming only happens when a
        // deadline exists, so a stale socket timeout must be cleared here.
        self.stream.set_read_timeout(timeout).map_err(map_io)?;
        self.stream.set_write_timeout(timeout).map_err(map_io)?;
        self.io_timeout = timeout;
        Ok(())
    }

    /// Best-effort close of both directions (idempotent; errors ignored —
    /// the session is already over when this is called).
    pub fn shutdown(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    /// Fix the deadline for one whole frame.
    fn frame_deadline(&self) -> Option<Instant> {
        self.io_timeout.map(|t| Instant::now() + t)
    }

    /// Re-arm the socket timeout to the time REMAINING before `deadline`
    /// (so a dripping peer cannot restart the clock per syscall), or fail
    /// with the timeout abort once the deadline has passed.
    fn rearm(&self, deadline: Option<Instant>, read: bool) -> Result<()> {
        let Some(deadline) = deadline else { return Ok(()) };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Abort("peer i/o timed out"));
        }
        let remaining = remaining.max(MIN_REARM);
        if read {
            self.stream.set_read_timeout(Some(remaining)).map_err(map_io)
        } else {
            self.stream.set_write_timeout(Some(remaining)).map_err(map_io)
        }
    }

    /// `read_exact` with a whole-frame deadline across partial reads.
    fn read_full(&mut self, buf: &mut [u8], deadline: Option<Instant>) -> Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            self.rearm(deadline, true)?;
            match self.stream.read(&mut buf[filled..]) {
                Ok(0) => return Err(Error::Abort("peer hung up")),
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(map_io(e)),
            }
        }
        Ok(())
    }

    /// `write_all` with a whole-frame deadline across partial writes.
    fn write_full(&mut self, buf: &[u8], deadline: Option<Instant>) -> Result<()> {
        let mut written = 0;
        while written < buf.len() {
            self.rearm(deadline, false)?;
            match self.stream.write(&buf[written..]) {
                Ok(0) => return Err(Error::Abort("peer hung up")),
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(map_io(e)),
            }
        }
        Ok(())
    }
}

impl Transport for TcpTransport {
    fn send(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_FRAME as usize {
            return Err(Error::Validation("frame exceeds MAX_FRAME"));
        }
        let len = bytes.len() as u32; // fits: checked against MAX_FRAME above
        let deadline = self.frame_deadline(); // one deadline for header + payload
        self.write_full(&len.to_be_bytes(), deadline)?;
        self.write_full(bytes, deadline)?;
        self.stream.flush().map_err(map_io)
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        let deadline = self.frame_deadline(); // one deadline for header + payload
        let mut header = [0u8; 4];
        self.read_full(&mut header, deadline)?;
        let len = u32::from_be_bytes(header);
        if len > MAX_FRAME {
            // Reject BEFORE allocating: a hostile header must not size a buffer.
            return Err(Error::Validation("frame exceeds MAX_FRAME"));
        }
        let mut payload = vec![0u8; len as usize];
        self.read_full(&mut payload, deadline)?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loopback pair: connect completes via the listener backlog, so no
    /// thread is needed for the handshake itself.
    fn pair() -> (TcpTransport, TcpTransport) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpTransport::connect(addr).expect("connect");
        let server = TcpTransport::accept(&listener).expect("accept");
        (client, server)
    }

    /// A raw (unframed) peer plus a TcpTransport on the other end, for
    /// injecting hand-built bytes at the socket level.
    fn raw_pair() -> (TcpStream, TcpTransport) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let raw = TcpStream::connect(addr).expect("connect");
        let server = TcpTransport::accept(&listener).expect("accept");
        (raw, server)
    }

    #[test]
    fn frames_round_trip_varied_sizes_in_order() {
        let (mut a, mut b) = pair();
        let frames: Vec<Vec<u8>> = vec![
            vec![],                                              // empty frame
            vec![0x42],                                          // 1 byte
            (0..=255u8).cycle().take(70_000).collect(),          // > socket buffer
            vec![0xA5; MAX_FRAME as usize],                      // exactly MAX_FRAME
            b"tail".to_vec(),                                    // ordering after the big one
        ];
        // The MAX_FRAME frame exceeds loopback socket buffers, so the sender
        // must run concurrently with the reader draining.
        let to_send = frames.clone();
        let sender = std::thread::spawn(move || {
            for f in &to_send {
                a.send(f).expect("send");
            }
            a
        });
        for f in &frames {
            assert_eq!(&b.recv().expect("recv"), f, "frame must round-trip byte-identical");
        }
        let mut a = sender.join().expect("sender thread");
        // Reverse direction over the same connection.
        b.send(b"pong").expect("send back");
        assert_eq!(a.recv().expect("recv back"), b"pong");
    }

    #[test]
    fn oversized_send_is_rejected_locally() {
        let (mut a, mut b) = pair();
        let big = vec![0u8; MAX_FRAME as usize + 1];
        match a.send(&big) {
            Err(Error::Validation(_)) => {}
            other => panic!("oversized send must be Validation, got {other:?}"),
        }
        // The rejected frame wrote nothing: the connection is still usable.
        a.send(b"still alive").expect("send after local reject");
        assert_eq!(b.recv().expect("recv"), b"still alive");
    }

    #[test]
    fn oversized_header_is_rejected_without_allocation() {
        let (mut raw, mut t) = raw_pair();
        // Hostile header claiming a 4 GiB frame; recv must reject on the
        // header alone (if it tried to allocate first, this would OOM-risk).
        raw.write_all(&u32::MAX.to_be_bytes()).expect("raw write");
        raw.flush().expect("flush");
        match t.recv() {
            Err(Error::Validation(_)) => {}
            other => panic!("oversized header must be Validation, got {other:?}"),
        }
    }

    #[test]
    fn split_header_and_chunked_payload_are_assembled() {
        let (mut raw, mut t) = raw_pair();
        let payload = vec![0xCD; 10_000];
        let expect = payload.clone();
        let hdr = (payload.len() as u32).to_be_bytes();
        let writer = std::thread::spawn(move || {
            // Header split across two writes, payload dribbled in chunks —
            // recv must loop on partial reads until the frame is whole.
            raw.write_all(&hdr[..2]).unwrap();
            raw.flush().unwrap();
            std::thread::sleep(Duration::from_millis(10));
            raw.write_all(&hdr[2..]).unwrap();
            raw.flush().unwrap();
            for chunk in payload.chunks(997) {
                raw.write_all(chunk).unwrap();
                raw.flush().unwrap();
            }
        });
        assert_eq!(t.recv().expect("recv"), expect);
        writer.join().expect("writer");
    }

    #[test]
    fn drip_feeding_peer_cannot_extend_the_frame_deadline() {
        let (mut raw, mut t) = raw_pair();
        t.set_io_timeout(Some(Duration::from_millis(200))).expect("timeout");
        // Peer promises 10 bytes, then drips one byte per 50 ms: each byte
        // lands well inside a PER-READ window, so a per-syscall timeout
        // would assemble the frame (~500 ms) and return Ok. The whole-frame
        // deadline must abort at ~200 ms instead.
        let writer = std::thread::spawn(move || {
            let _ = raw.write_all(&10u32.to_be_bytes());
            let _ = raw.flush();
            for _ in 0..10 {
                std::thread::sleep(Duration::from_millis(50));
                if raw.write_all(&[0xEE]).is_err() {
                    break;
                }
                let _ = raw.flush();
            }
        });
        let started = Instant::now();
        match t.recv() {
            Err(Error::Abort(msg)) => assert_eq!(msg, "peer i/o timed out"),
            other => panic!("dripped frame must hit the deadline, got {other:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "deadline must not stretch per dripped byte"
        );
        writer.join().expect("writer");
    }

    #[test]
    fn dead_peer_surfaces_err_on_recv() {
        let (a, mut b) = pair();
        drop(a); // peer hangs up
        match b.recv() {
            Err(Error::Abort(_)) => {}
            other => panic!("recv from dead peer must be Abort, got {other:?}"),
        }
    }

    #[test]
    fn dead_peer_surfaces_err_on_send() {
        let (a, mut b) = pair();
        drop(a);
        // Keep the test bounded even if the OS buffers generously.
        b.set_io_timeout(Some(Duration::from_millis(500))).expect("timeout");
        let frame = vec![0u8; 4096];
        let mut got_err = false;
        for _ in 0..2048 {
            // 8 MiB total — far beyond any socket buffer
            if b.send(&frame).is_err() {
                got_err = true;
                break;
            }
        }
        assert!(got_err, "sending to a dead peer must surface Err");
    }

    #[test]
    fn silent_peer_times_out_as_abort() {
        let (_a, mut b) = pair(); // _a alive but silent — no EOF, no data
        b.set_io_timeout(Some(Duration::from_millis(100))).expect("timeout");
        match b.recv() {
            Err(Error::Abort(msg)) => assert_eq!(msg, "peer i/o timed out"),
            other => panic!("silent peer must time out as Abort, got {other:?}"),
        }
    }

    #[test]
    fn accept_timeout_expires_without_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let started = Instant::now();
        match TcpTransport::accept_timeout(&listener, Duration::from_millis(150)) {
            Err(Error::Abort(_)) => {}
            Ok(_) => panic!("no peer connected — accept must time out"),
            Err(other) => panic!("expected Abort, got {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(5), "accept wait must be bounded");
    }

    #[test]
    fn accept_timeout_yields_a_usable_blocking_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut client = TcpTransport::connect(addr).expect("connect");
        let mut server =
            TcpTransport::accept_timeout(&listener, Duration::from_secs(5)).expect("accept");
        client.send(b"over accept_timeout").expect("send");
        assert_eq!(server.recv().expect("recv"), b"over accept_timeout");
        // And the accepted socket is truly blocking: a silent wait must ride
        // the frame deadline, not spin out a nonblocking WouldBlock instantly.
        server.set_io_timeout(Some(Duration::from_millis(100))).expect("timeout");
        let started = Instant::now();
        assert!(server.recv().is_err());
        assert!(started.elapsed() >= Duration::from_millis(50), "must block, not spin");
    }

    #[test]
    fn connect_to_closed_port_fails() {
        // Bind then drop to get a port that is (momentarily) closed.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        match TcpTransport::connect(addr) {
            Err(Error::Abort(_)) => {}
            Ok(_) => panic!("connect to closed port must fail"),
            Err(other) => panic!("expected Abort, got {other:?}"),
        }
    }

    #[test]
    fn zero_timeout_is_a_config_error() {
        let (mut a, _b) = pair();
        match a.set_io_timeout(Some(Duration::ZERO)) {
            Err(Error::Validation(_)) => {}
            other => panic!("zero timeout must be Validation, got {other:?}"),
        }
        match TcpTransport::accept_timeout(
            &TcpListener::bind("127.0.0.1:0").expect("bind"),
            Duration::ZERO,
        ) {
            Err(Error::Validation(_)) => {}
            other => panic!("zero accept timeout must be Validation, got {other:?}"),
        }
    }

    // ---- Task 24: dial-retry + timeout-ladder ----

    #[test]
    fn negotiation_io_timeout_floors_at_120s_then_scales_with_poll() {
        // At/below a 40 s poll the 120 s floor binds...
        for secs in [1u64, 5, 40] {
            assert_eq!(
                negotiation_io_timeout(Duration::from_secs(secs)),
                Duration::from_secs(120),
                "poll {secs}s must floor at 120s"
            );
        }
        // ...above it, 3× the poll cadence.
        assert_eq!(negotiation_io_timeout(Duration::from_secs(60)), Duration::from_secs(180));
        assert_eq!(negotiation_io_timeout(Duration::from_secs(100)), Duration::from_secs(300));
    }

    // The retry POLICY is tested deterministically against an injected dial op
    // (no real sockets — Windows loopback connect-to-closed-port timing is not
    // portable), and `connect_retrying` is smoke-tested on a live listener.

    fn refused() -> std::io::Error {
        std::io::Error::from(std::io::ErrorKind::ConnectionRefused)
    }

    #[test]
    fn dial_with_retry_is_bounded_and_returns_the_last_error() {
        // Always-refused: retries EXACTLY `retries` times (one log per retry),
        // then gives up returning the last (transient) error unchanged.
        let mut logs = 0usize;
        let mut log = |_l: String| logs += 1;
        let r: std::io::Result<()> =
            dial_with_retry(3, Duration::ZERO, &mut log, || Err(refused()));
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::ConnectionRefused);
        assert_eq!(logs, 3, "must retry exactly `retries` times before give-up");
    }

    #[test]
    fn dial_with_retry_does_not_retry_a_permanent_error() {
        // A permanent (non-transient) error fails on the first attempt.
        let mut logs = 0usize;
        let mut log = |_l: String| logs += 1;
        let r: std::io::Result<()> = dial_with_retry(5, Duration::ZERO, &mut log, || {
            Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
        });
        assert!(r.is_err());
        assert_eq!(logs, 0, "a permanent error must not retry");
    }

    #[test]
    fn dial_with_retry_recovers_after_transient_failures() {
        // Refused twice, then succeeds: Ok after exactly two retries.
        let mut calls = 0u32;
        let mut logs = 0usize;
        let mut log = |_l: String| logs += 1;
        let r: std::io::Result<u8> = dial_with_retry(5, Duration::ZERO, &mut log, || {
            calls += 1;
            if calls <= 2 {
                Err(refused())
            } else {
                Ok(0xABu8)
            }
        });
        assert_eq!(r.expect("recovers once the dial succeeds"), 0xAB);
        assert_eq!(logs, 2, "retried exactly the two transient failures");
        assert_eq!(calls, 3, "the third attempt succeeded");
    }

    #[test]
    fn connect_retrying_connects_to_a_live_listener_first_try() {
        // The real path over loopback: a live listener connects on attempt one
        // (zero retries) and the resulting transport carries a frame.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let mut logs = 0usize;
        let mut log = |_l: String| logs += 1;
        let mut client = TcpTransport::connect_retrying(&addr, 3, Duration::from_millis(5), &mut log)
            .expect("connect to a live listener");
        let mut server = TcpTransport::accept(&listener).expect("accept");
        assert_eq!(logs, 0, "a live listener needs no retry");
        client.send(b"over connect_retrying").expect("send");
        assert_eq!(server.recv().expect("recv"), b"over connect_retrying");
    }

    #[test]
    fn connect_retrying_fails_fast_on_a_malformed_address() {
        // A malformed address is a permanent InvalidInput from the real
        // TcpStream::connect — no retry, prompt clean error.
        let mut logs = 0usize;
        let mut log = |_l: String| logs += 1;
        let r =
            TcpTransport::connect_retrying("not a socket address", 5, Duration::from_millis(5), &mut log);
        assert!(r.is_err(), "a malformed address must fail");
        assert_eq!(logs, 0, "a permanent dial error must not retry");
    }
}
