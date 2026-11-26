//! Sans-IO SRT (Secure Reliable Transport) live mode, interoperable with
//! libsrt 1.5.7: HSv5 caller and listener, TSBPD delivery, ACK/ACKACK, NAK and
//! retransmission, keepalive,
//! shutdown, peer idle timeout. No sockets, threads or clock reads: every
//! entry point takes `now`. See DESIGN.md.
//!
//! Loss recovery: receiver loss list with a NAK schedule per hole, sender
//! retransmission ahead of new data, DROPREQ, sender drop and a tail probe
//! (spec 6, 7, 12). The libsrt `fec` packet filter (spec 8): row/column
//! XOR groups in both layouts, iterative rebuild, arq never/onreq/always
//! with NAKs that, unlike libsrt's, are repeated (`fec`).

pub mod config;
pub mod conn;
#[cfg(feature = "aes")]
pub mod crypto;
pub mod fec;
pub mod filter;
pub mod handshake;
pub mod listener;
mod losslist;
pub mod packet;
mod pool;
mod rcvbuf;
pub mod seq;
mod sndbuf;
pub mod stats;
pub mod tsbpd;

pub use config::Config;
pub use conn::{CloseReason, Connection, Delivered, Event, Role, SendError, State, Transmit};
pub use handshake::RejectReason;
pub use listener::{random_isn, random_socket_id, AcceptCallback, AcceptRequest, AcceptSecretCallback, Listener, ListenerAction, ListenerStats};
pub use stats::{DroppedHole, Snapshot, Stats};
