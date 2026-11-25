//! Safe Rust SRT (Secure Reliable Transport) for Wavey, with two backends
//! behind one API:
//!
//! - `libsrt` (default feature): the vendored libsrt 1.4.4 through `srt-sys`
//!   (bindgen, cmake and a C/C++ compiler at build time).
//! - `pure-rust`: `srt-core` (sans-IO live-mode SRT, interoperable with
//!   libsrt) driven by `srt-mio` on one I/O thread per listener or caller,
//!   bridged to the caller's threads (and to tokio with `async`) by bounded
//!   queues and wakers. No C code. Build it with
//!   `default-features = false, features = ["pure-rust", ...]` so `srt-sys`
//!   is not compiled; if both are enabled, `pure-rust` is used.
//!
//! The types below are shared by both backends; `Listener`, `Stream`,
//! `AsyncListener` and `AsyncStream` come from the backend in use.

#[cfg(all(feature = "libsrt", not(feature = "pure-rust")))]
#[macro_use]
extern crate lazy_static;

#[cfg(not(any(feature = "libsrt", feature = "pure-rust")))]
compile_error!("wavey-srt: enable the `libsrt` (default) or the `pure-rust` feature");

use libc::{LOG_CRIT, LOG_DEBUG, LOG_ERR, LOG_NOTICE, LOG_WARNING};
use std::{ffi::c_int, fmt, io, str};

#[cfg(all(feature = "libsrt", not(feature = "pure-rust")))]
mod libsrt;
#[cfg(all(feature = "libsrt", not(feature = "pure-rust")))]
pub use libsrt::*;

#[cfg(feature = "pure-rust")]
mod pure;
#[cfg(feature = "pure-rust")]
pub use pure::*;

/// The backend this build uses: `"libsrt"` or `"pure-rust"`.
#[cfg(feature = "pure-rust")]
pub const BACKEND: &str = "pure-rust";
/// The backend this build uses: `"libsrt"` or `"pure-rust"`.
#[cfg(not(feature = "pure-rust"))]
pub const BACKEND: &str = "libsrt";

#[derive(Debug)]
pub enum Error {
    InvalidAddress,
    UnsupportedFamily(c_int),
    IOError(io::Error),
    Utf8Error(str::Utf8Error),
    /// An SRT error: `code` is libsrt's `SRT_ERRNO` (both backends use the
    /// same numbers, e.g. 2001 = connection lost, 1001 = no server / connect
    /// timeout, 1002 = rejected), `errno` the system errno if any.
    SRTError {
        fn_name: &'static str,
        code: c_int,
        errno: c_int,
    },
    #[cfg(feature = "async")]
    JoinError(tokio::task::JoinError),
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::IOError(e)
    }
}

impl From<str::Utf8Error> for Error {
    fn from(e: str::Utf8Error) -> Self {
        Self::Utf8Error(e)
    }
}

#[cfg(feature = "async")]
impl From<tokio::task::JoinError> for Error {
    fn from(e: tokio::task::JoinError) -> Error {
        Error::JoinError(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress => write!(f, "invalid address"),
            Self::UnsupportedFamily(family) => write!(f, "unsupported family: {}", family),
            Self::IOError(e) => write!(f, "io error: {}", e),
            Self::Utf8Error(e) => write!(f, "utf8 error: {}", e),
            Self::SRTError { fn_name, code, errno } => write!(f, "{} error: {} (errno = {})", fn_name, code, errno),
            #[cfg(feature = "async")]
            Self::JoinError(e) => write!(f, "join error: {}", e),
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub trait ListenerCallback: Send + Sync {
    fn callback(&self, stream_id: Option<&str>) -> ListenerCallbackAction;
}

impl<T: Fn(Option<&str>) -> ListenerCallbackAction + Send + Sync> ListenerCallback for T {
    fn callback(&self, stream_id: Option<&str>) -> ListenerCallbackAction {
        (*self)(stream_id)
    }
}

pub enum ListenerCallbackAction {
    Deny,
    Allow { passphrase: Option<String> },
}

#[derive(Clone, Debug)]
pub enum ListenerOption {
    TimestampBasedPacketDeliveryMode(bool),
    PeerLatency(i32),
    TooLatePacketDrop(bool),
    ReceiveBufferSize(i32),
    SendBufferSize(i32),
}

#[derive(Clone, Debug)]
pub enum MaxBandwidth {
    Infinite,
    Relative { input_bandwidth: u64, overhead_bandwidth_percentage: u32 },
    Absolute(u64),
}

#[derive(Clone, Debug, Default)]
pub struct ConnectOptions {
    pub passphrase: Option<String>,
    pub stream_id: Option<String>,
    pub timestamp_based_packet_delivery_mode: Option<bool>,
    pub too_late_packet_drop: Option<bool>,
    pub receive_buffer_size: Option<i32>,
    pub send_buffer_size: Option<i32>,
    pub max_bandwidth: Option<MaxBandwidth>,
    pub max_send_payload_size: Option<i32>,
}

#[repr(i32)]
#[derive(num_derive::FromPrimitive, num_derive::ToPrimitive, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Debug = LOG_DEBUG,
    Notice = LOG_NOTICE,
    Warning = LOG_WARNING,
    Error = LOG_ERR,
    Critical = LOG_CRIT,
}

pub struct SrtLogEvent<'a> {
    /// The logging level
    pub level: LogLevel,
    /// The file where the log statement was found
    pub file: Option<&'a str>,
    /// The line number where the log statement was found
    pub line: c_int,
    /// The area of concern
    pub area: Option<&'a str>,
    /// The message that was logged
    pub message: Option<&'a str>,
}

#[cfg(test)]
mod api_test {
    use super::*;

    #[test]
    fn error_display_matches_libsrt_wrapper() {
        let e = Error::SRTError {
            fn_name: "srt_recv",
            code: 2001,
            errno: 0,
        };
        assert_eq!(e.to_string(), "srt_recv error: 2001 (errno = 0)");
        let io = io::Error::new(io::ErrorKind::Other, e);
        assert!(io.to_string().contains("srt_recv error: 2001"));
    }

    #[test]
    fn backend_name() {
        assert!(BACKEND == "libsrt" || BACKEND == "pure-rust");
    }
}
