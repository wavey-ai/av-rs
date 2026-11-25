//! Sans-IO SRT (Secure Reliable Transport) live mode, interoperable with
//! libsrt 1.5.7: HSv5 caller and listener, TSBPD delivery, ACK/ACKACK, keepalive,
//! shutdown, peer idle timeout. No sockets, threads or clock reads: every
//! entry point takes `now`. See DESIGN.md.
//!
//! Loss recovery (NAK/retransmission) and the FEC packet filter are later
//! stages; packet-filter configs are already negotiated and carried.

pub mod config;
pub mod conn;
pub mod filter;
pub mod handshake;
pub mod listener;
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
pub use listener::{random_isn, random_socket_id, AcceptCallback, AcceptRequest, Listener, ListenerAction, ListenerStats};
pub use stats::{Snapshot, Stats};
