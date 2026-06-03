#[macro_use]
extern crate lazy_static;

use libc::{sockaddr_in, sockaddr_in6, LOG_CRIT, LOG_DEBUG, LOG_ERR, LOG_NOTICE, LOG_WARNING};
use num_traits::FromPrimitive;
pub use srt_sys as sys;
use std::{
    any::Any,
    borrow::Cow,
    ffi::{c_char, c_int, CStr},
    fmt,
    io::{self, Read, Write},
    mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    os::raw::c_void,
    panic,
    pin::Pin,
    process::abort,
    str,
    sync::{atomic::AtomicUsize, Arc, Mutex},
};
use sys::{srt_setloghandler, srt_setloglevel};

#[cfg(feature = "async")]
mod async_lib;
#[cfg(feature = "async")]
mod epoll_reactor;
#[cfg(feature = "async")]
pub use async_lib::*;

#[derive(Debug)]
pub enum Error {
    InvalidAddress,
    UnsupportedFamily(sys::int),
    IOError(io::Error),
    Utf8Error(str::Utf8Error),
    SRTError {
        fn_name: &'static str,
        code: sys::int,
        errno: sys::int,
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

type Result<T> = std::result::Result<T, Error>;

pub(crate) fn new_io_error(fn_name: &'static str) -> io::Error {
    let mut errno = 0;
    let code = unsafe { sys::srt_getlasterror(&mut errno as _) };
    io::Error::new(io::ErrorKind::Other, Error::SRTError { fn_name, code, errno })
}

pub(crate) fn new_srt_error(fn_name: &'static str) -> Error {
    let mut errno = 0;
    let code = unsafe { sys::srt_getlasterror(&mut errno as _) };
    Error::SRTError { fn_name, code, errno }
}

fn check_code(fn_name: &'static str, code: sys::int) -> Result<()> {
    match code {
        0 => Ok(()),
        _ => Err(new_srt_error(fn_name)),
    }
}

#[derive(Default)]
struct Api {
    #[cfg(feature = "async")]
    state: Arc<ApiState>,
}

#[derive(Default)]
struct ApiState {
    #[cfg(feature = "async")]
    epoll_reactor: Mutex<Option<Arc<epoll_reactor::EpollReactor>>>,
    ref_count: AtomicUsize,
}

lazy_static! {
    static ref GLOBAL_API_STATE: Mutex<Arc<ApiState>> = Mutex::new(Arc::new(ApiState::default()));
}

impl Api {
    #[cfg(feature = "async")]
    fn get_epoll_reactor(&self) -> Result<Arc<epoll_reactor::EpollReactor>> {
        let mut api_reactor = self.state.epoll_reactor.lock().expect("the lock should not be poisoned");
        match &*api_reactor {
            Some(api_reactor) => Ok(api_reactor.clone()),
            None => {
                let r = Arc::new(epoll_reactor::EpollReactor::new()?);
                *api_reactor = Some(r.clone());
                Ok(r)
            }
        }
    }

    fn get() -> Result<Arc<Api>> {
        let api_state = GLOBAL_API_STATE.lock().unwrap();
        if api_state.ref_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            unsafe {
                check_code("srt_startup", sys::srt_startup())?;
            }
        }
        Ok(Arc::new(Api {
            #[cfg(feature = "async")]
            state: api_state.clone(),
        }))
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        let api_state = GLOBAL_API_STATE.lock().unwrap();
        if api_state.ref_count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
            #[cfg(feature = "async")]
            if let Some(reactor) = api_state.epoll_reactor.lock().expect("the lock should not be poisoned").take() {
                if Arc::try_unwrap(reactor).is_err() {
                    panic!("the api must have the last strong reference to the reactor");
                }
            }

            unsafe {
                sys::srt_cleanup();
            }
        }
    }
}

struct Socket {
    pub(crate) api: Arc<Api>,
    sock: sys::SRTSOCKET,
}

trait ToOption {
    fn set(&self, sock: sys::SRTSOCKET, opt: sys::SRT_SOCKOPT) -> Result<()>;
}

impl ToOption for &String {
    fn set(&self, sock: sys::SRTSOCKET, opt: sys::SRT_SOCKOPT) -> Result<()> {
        check_code("srt_setsockopt", unsafe {
            sys::srt_setsockopt(sock, 0, opt, self.as_ptr() as *const _, self.len() as _)
        })
    }
}

impl ToOption for bool {
    fn set(&self, sock: sys::SRTSOCKET, opt: sys::SRT_SOCKOPT) -> Result<()> {
        check_code("srt_setsockopt", unsafe {
            sys::srt_setsockopt(sock, 0, opt, self as *const bool as *const _, std::mem::size_of::<bool>() as _)
        })
    }
}

impl ToOption for i32 {
    fn set(&self, sock: sys::SRTSOCKET, opt: sys::SRT_SOCKOPT) -> Result<()> {
        check_code("srt_setsockopt", unsafe {
            sys::srt_setsockopt(sock, 0, opt, self as *const i32 as *const _, std::mem::size_of::<i32>() as _)
        })
    }
}

impl ToOption for i64 {
    fn set(&self, sock: sys::SRTSOCKET, opt: sys::SRT_SOCKOPT) -> Result<()> {
        check_code("srt_setsockopt", unsafe {
            sys::srt_setsockopt(sock, 0, opt, self as *const i64 as *const _, std::mem::size_of::<i64>() as _)
        })
    }
}

trait FromOption: Sized {
    fn get(sock: sys::SRTSOCKET, opt: sys::SRT_SOCKOPT) -> Result<Self>;
}

impl FromOption for Option<String> {
    fn get(sock: sys::SRTSOCKET, opt: sys::SRT_SOCKOPT) -> Result<Self> {
        let mut buf = [0u8; 512];
        let mut len = buf.len();
        check_code("srt_getsockopt", unsafe {
            sys::srt_getsockopt(sock, 0, opt, buf.as_mut_ptr() as *mut _, &mut len as *mut _ as *mut _)
        })?;
        Ok(match len {
            0 => None,
            len => Some(str::from_utf8(&buf[..len])?.to_string()),
        })
    }
}

impl FromOption for i32 {
    fn get(sock: sys::SRTSOCKET, opt: sys::SRT_SOCKOPT) -> Result<Self> {
        let mut n = 0i32;
        let mut n_len = std::mem::size_of::<i32>() as sys::int;
        check_code("srt_getsockopt", unsafe {
            sys::srt_getsockopt(sock, 0, opt, &mut n as *mut i32 as _, &mut n_len as *mut _)
        })?;
        Ok(n)
    }
}

impl Socket {
    fn new() -> Result<Socket> {
        Ok(Socket {
            api: Api::get()?,
            sock: unsafe { sys::srt_create_socket() },
        })
    }

    fn raw(&self) -> sys::SRTSOCKET {
        self.sock
    }

    #[cfg(test)]
    fn socket_addr(&self) -> Result<SocketAddr> {
        use std::mem::MaybeUninit;

        use sys::{sockaddr, srt_getsockname};

        unsafe {
            // Try IPv4 first, if that fails try IPv6.
            let mut ipv4: MaybeUninit<sockaddr_in> = MaybeUninit::uninit();
            let mut len = mem::size_of::<sockaddr_in>() as i32;
            let success = srt_getsockname(self.sock, ipv4.as_mut_ptr() as *mut sockaddr, &mut len) == 0;
            if success && len == mem::size_of::<sockaddr_in>() as i32 {
                let ipv4 = ipv4.assume_init();
                Ok(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(ipv4.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be_bytes(ipv4.sin_port.to_ne_bytes()),
                )))
            } else {
                let mut ipv6: MaybeUninit<sockaddr_in6> = MaybeUninit::uninit();
                let mut len = mem::size_of::<sockaddr_in6>() as i32;
                let success = srt_getsockname(self.sock, ipv6.as_mut_ptr() as *mut sockaddr, &mut len) == 0;
                if success && len == mem::size_of::<sockaddr_in6>() as i32 {
                    let ipv6 = ipv6.assume_init();
                    Ok(SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::from(ipv6.sin6_addr.s6_addr),
                        u16::from_be_bytes(ipv6.sin6_port.to_ne_bytes()),
                        ipv6.sin6_flowinfo,
                        ipv6.sin6_scope_id,
                    )))
                } else if !success {
                    Err(io::Error::last_os_error().into())
                } else {
                    panic!("This function only supports IPv4 and IPv6")
                }
            }
        }
    }

    fn raw_stats(&mut self, clear: bool, instantaneous: bool) -> Result<sys::SRT_TRACEBSTATS> {
        unsafe {
            let mut perf = mem::MaybeUninit::<sys::SRT_TRACEBSTATS>::zeroed();
            check_code(
                "srt_bistats",
                sys::srt_bistats(self.raw(), perf.as_mut_ptr(), if clear { 1 } else { 0 }, if instantaneous { 1 } else { 0 }),
            )?;
            Ok(perf.assume_init())
        }
    }

    fn set_connect_options(&self, options: &ConnectOptions) -> Result<()> {
        if let Some(v) = &options.passphrase {
            self.set(sys::SRT_SOCKOPT_SRTO_PASSPHRASE, v)?;
        }
        if let Some(v) = &options.stream_id {
            self.set(sys::SRT_SOCKOPT_SRTO_STREAMID, v)?;
        }
        if let Some(v) = &options.too_late_packet_drop {
            self.set(sys::SRT_SOCKOPT_SRTO_TLPKTDROP, *v)?;
        }
        if let Some(v) = &options.timestamp_based_packet_delivery_mode {
            self.set(sys::SRT_SOCKOPT_SRTO_TSBPDMODE, *v)?;
        }
        if let Some(v) = &options.receive_buffer_size {
            self.set(sys::SRT_SOCKOPT_SRTO_RCVBUF, *v)?;
        }
        if let Some(v) = &options.send_buffer_size {
            self.set(sys::SRT_SOCKOPT_SRTO_SNDBUF, *v)?;
        }
        if let Some(v) = &options.max_bandwidth {
            match v {
                MaxBandwidth::Infinite => self.set(sys::SRT_SOCKOPT_SRTO_MAXBW, -1i64)?,
                MaxBandwidth::Relative {
                    input_bandwidth,
                    overhead_bandwidth_percentage,
                } => {
                    self.set(sys::SRT_SOCKOPT_SRTO_MAXBW, 0i64)?;
                    self.set(sys::SRT_SOCKOPT_SRTO_INPUTBW, *input_bandwidth as i64)?;
                    self.set(sys::SRT_SOCKOPT_SRTO_OHEADBW, *overhead_bandwidth_percentage as i32)?;
                }
                MaxBandwidth::Absolute(n) => self.set(sys::SRT_SOCKOPT_SRTO_MAXBW, *n as i64)?,
            }
        }
        if let Some(v) = &options.max_send_payload_size {
            self.set(sys::SRT_SOCKOPT_SRTO_PAYLOADSIZE, *v)?;
        }
        Ok(())
    }

    fn set<T: ToOption>(&self, opt: sys::SRT_SOCKOPT, value: T) -> Result<()> {
        value.set(self.sock, opt)
    }

    fn get<T: FromOption>(&self, opt: sys::SRT_SOCKOPT) -> Result<T> {
        T::get(self.sock, opt)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe {
            sys::srt_close(self.sock);
        }
    }
}

fn sockaddr_from_storage(storage: &sys::sockaddr_storage, len: sys::socklen_t) -> Result<SocketAddr> {
    // from: https://github.com/rust-lang/rust/blob/7c78a5f97de07a185eebae5a5de436c80d8ba9d4/src/libstd/sys_common/net.rs#L95
    use libc::{c_int, AF_INET, AF_INET6};
    match storage.ss_family as c_int {
        AF_INET => {
            assert!(len as usize >= mem::size_of::<sockaddr_in>());
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(unsafe { u32::from_be((*(storage as *const _ as *const sockaddr_in)).sin_addr.s_addr) }),
                unsafe { u16::from_be((*(storage as *const _ as *const sockaddr_in)).sin_port) },
            )))
        }
        AF_INET6 => {
            assert!(len as usize >= mem::size_of::<sockaddr_in6>());
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(unsafe { (*(storage as *const _ as *const sockaddr_in6)).sin6_addr.s6_addr }),
                unsafe { u16::from_be((*(storage as *const _ as *const sockaddr_in6)).sin6_port) },
                unsafe { u32::from_be((*(storage as *const _ as *const sockaddr_in6)).sin6_flowinfo) },
                unsafe { u32::from_be((*(storage as *const _ as *const sockaddr_in6)).sin6_scope_id) },
            )))
        }
        f => Err(Error::UnsupportedFamily(f)),
    }
}

fn to_sockaddr(addr: &SocketAddr) -> (sys::sockaddr_storage, sys::socklen_t) {
    use libc::{AF_INET, AF_INET6};
    let mut storage = mem::MaybeUninit::<sys::sockaddr_storage>::zeroed();
    let socklen = match addr {
        SocketAddr::V4(ref a) => {
            let storage = unsafe { &mut *(storage.as_mut_ptr() as *mut sockaddr_in) };
            storage.sin_family = AF_INET as _;
            storage.sin_port = u16::to_be(a.port());
            storage.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
            mem::size_of::<sockaddr_in>()
        }
        SocketAddr::V6(ref a) => {
            let storage = unsafe { &mut *(storage.as_mut_ptr() as *mut sockaddr_in6) };
            storage.sin6_family = AF_INET6 as _;
            storage.sin6_port = u16::to_be(a.port());
            storage.sin6_addr.s6_addr.copy_from_slice(&a.ip().octets());
            mem::size_of::<sockaddr_in6>()
        }
    };
    (unsafe { storage.assume_init() }, socklen as _)
}

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

pub struct Listener<'c> {
    socket: Socket,

    // we pass a pointer to `Box<dyn ListenerCallback + 'c>` to C land, and the double boxing is
    // necessary here to keep that pointer valid
    #[allow(clippy::redundant_allocation)]
    _callback: Option<Pin<Box<Box<dyn ListenerCallback + 'c>>>>,
}

extern "C" fn listener_callback(
    opaq: *mut sys::void,
    ns: sys::SRTSOCKET,
    _hs_version: sys::int,
    _peer: *const sys::sockaddr,
    stream_id: *const sys::char,
) -> sys::int {
    unsafe {
        let f = opaq as *mut Box<dyn ListenerCallback>;
        let stream_id = if stream_id.is_null() { None } else { CStr::from_ptr(stream_id).to_str().ok() };
        match (*f).callback(stream_id) {
            ListenerCallbackAction::Deny => -1,
            ListenerCallbackAction::Allow { passphrase } => {
                if let Some(v) = &passphrase {
                    if v.set(ns, sys::SRT_SOCKOPT_SRTO_PASSPHRASE).is_err() {
                        return -1;
                    }
                }
                0
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum ListenerOption {
    TimestampBasedPacketDeliveryMode(bool),
    PeerLatency(i32),
    TooLatePacketDrop(bool),
    ReceiveBufferSize(i32),
    SendBufferSize(i32),
}

impl ListenerOption {
    pub(crate) fn set(&self, sock: &Socket) -> Result<()> {
        match self {
            ListenerOption::TimestampBasedPacketDeliveryMode(v) => sock.set(sys::SRT_SOCKOPT_SRTO_TSBPDMODE, *v),
            ListenerOption::PeerLatency(v) => sock.set(sys::SRT_SOCKOPT_SRTO_PEERLATENCY, *v),
            ListenerOption::TooLatePacketDrop(v) => sock.set(sys::SRT_SOCKOPT_SRTO_TLPKTDROP, *v),
            ListenerOption::ReceiveBufferSize(v) => sock.set(sys::SRT_SOCKOPT_SRTO_RCVBUF, *v),
            ListenerOption::SendBufferSize(v) => sock.set(sys::SRT_SOCKOPT_SRTO_SNDBUF, *v),
        }
    }
}

impl Listener<'static> {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        Self::bind_with_options(addr, vec![])
    }

    pub fn bind_with_options<A: ToSocketAddrs, O: IntoIterator<Item = ListenerOption>>(addr: A, opts: O) -> Result<Self> {
        let socket = Socket::new()?;
        for opt in opts.into_iter() {
            opt.set(&socket)?;
        }
        for addr in addr.to_socket_addrs()? {
            let (addr, len) = to_sockaddr(&addr);
            unsafe {
                check_code("srt_bind", sys::srt_bind(socket.raw(), &addr as *const _ as _, len as _))?;
            }
        }
        unsafe {
            check_code("srt_listen", sys::srt_listen(socket.raw(), 10))?;
        }
        Ok(Self { socket, _callback: None })
    }
}

impl<'c> Listener<'c> {
    pub fn with_callback<F: ListenerCallback + 'c>(self, f: F) -> Result<Listener<'c>> {
        let mut cb: Box<Box<dyn ListenerCallback>> = Box::new(Box::new(f));
        let ptr = &mut *cb as *mut Box<dyn ListenerCallback>;
        let pb = unsafe { Pin::new_unchecked(cb) };
        check_code("srt_listen_callback", unsafe {
            sys::srt_listen_callback(self.socket.raw(), Some(listener_callback), ptr as *mut _)
        })?;
        Ok(Listener {
            _callback: Some(pb),
            socket: self.socket,
        })
    }

    pub fn accept(&self) -> Result<(Stream, SocketAddr)> {
        let mut storage = mem::MaybeUninit::<sys::sockaddr_storage>::zeroed();
        let mut len = mem::size_of_val(&storage) as sys::socklen_t;
        let (storage, socket) = unsafe {
            let sock = sys::srt_accept(self.socket.raw(), storage.as_mut_ptr() as *mut _, &mut len as *mut _ as *mut _);
            let socket = Socket {
                api: self.socket.api.clone(),
                sock,
            };
            (storage.assume_init(), socket)
        };
        let addr = sockaddr_from_storage(&storage, len)?;
        let max_send_payload_size = socket
            .get::<i32>(sys::SRT_SOCKOPT_SRTO_PAYLOADSIZE)
            .expect("SRT should have a default payload size if not set") as _;
        Ok((
            Stream {
                id: socket.get(sys::SRT_SOCKOPT_SRTO_STREAMID)?,
                socket,
                max_send_payload_size,
            },
            addr,
        ))
    }
}

pub struct Stream {
    socket: Socket,
    id: Option<String>,
    max_send_payload_size: usize,
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

impl Stream {
    pub fn connect<A: ToSocketAddrs>(addr: A, options: &ConnectOptions) -> Result<Self> {
        let mut last_err = Error::InvalidAddress;
        for addr in addr.to_socket_addrs()? {
            let (addr, len) = to_sockaddr(&addr);
            let socket = Socket::new()?;
            socket.set_connect_options(options)?;
            unsafe {
                match check_code("srt_connect", sys::srt_connect(socket.raw(), &addr as *const _ as _, len as _)) {
                    Err(e) => last_err = e,
                    Ok(_) => {
                        let max_send_payload_size = socket
                            .get::<i32>(sys::SRT_SOCKOPT_SRTO_PAYLOADSIZE)
                            .expect("SRT should have a default payload size if not set") as _;
                        return Ok(Self {
                            socket,
                            id: options.stream_id.clone(),
                            max_send_payload_size,
                        });
                    }
                }
            }
        }
        Err(last_err)
    }

    pub fn id(&self) -> Option<&String> {
        self.id.as_ref()
    }

    /// Returns the underlying stats for the socket.
    ///
    /// Refer to https://github.com/Haivision/srt/blob/v1.4.4/docs/API/statistics.md to learn more about them.
    pub fn raw_stats(&mut self, clear: bool, instantaneous: bool) -> Result<sys::SRT_TRACEBSTATS> {
        self.socket.raw_stats(clear, instantaneous)
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match unsafe { sys::srt_recv(self.socket.raw(), buf.as_mut_ptr() as *mut sys::char, buf.len() as _) } {
            len if len >= 0 => Ok(len as usize),
            _ => Err(new_io_error("srt_recv")),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let data_size = if self.max_send_payload_size == 0 {
            // When set to 0, there's no limit for a single sending call.
            // https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md#SRTO_PAYLOADSIZE
            buf.len()
        } else {
            self.max_send_payload_size.min(buf.len())
        };
        match unsafe { sys::srt_send(self.socket.raw(), buf.as_ptr() as *const sys::char, data_size as _) } {
            len if len >= 0 => Ok(len as usize),
            _ => Err(new_io_error("srt_send")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Used internally to clean up a previously set log handler. Not strictly necessary, but a nice way to prevent leaks
/// if a log handler is set repeatedly.
static LOG_HANDLER: Mutex<Option<LogHandler>> = Mutex::new(None);

struct LogHandler(LogHandlerRaw);

// If this looks silly, keep in the mind the box contains a fat pointer. The libsrt API only takes a slim pointer.
// So this is a slim pointer pointing to a fat pointer, contained within a Box.
type LogHandlerRaw = *mut Box<dyn FnMut(&SrtLogEvent) + Send + Sync + 'static>;

// This is legal so long as the pointer is never used in two places at once. We synchronize this usage carefully in
// `set_log_handler`
unsafe impl Send for LogHandler {}

/// Sets the handler for logs generated by libsrt.
pub fn set_log_handler<F>(handler: F)
where
    F: FnMut(&SrtLogEvent) + Send + Sync + 'static,
{
    let closure_raw = Box::into_raw(Box::new(Box::new(handler) as Box<dyn FnMut(&SrtLogEvent) + Send + Sync + 'static>));
    let closure = LogHandler(closure_raw);
    let mut lock = LOG_HANDLER.lock().unwrap();
    let old_handler = mem::replace(&mut *lock, Some(closure));
    unsafe {
        srt_setloghandler(closure_raw as *mut c_void, Some(log_handler_adapter));
        // Now that old_handler is no longer being used, convert it back to a box and drop it.
        old_handler.map(|lh| Box::from_raw(lh.0));
    }
}

unsafe extern "C" fn log_handler_adapter(opaque: *mut c_void, level: c_int, file: *const c_char, line: c_int, area: *const c_char, message: *const c_char) {
    // Unwinding into C code is forbidden, so catch any unwinds here. The most likely reason this would fail is if a `Drop::drop` implementation panicked,
    // on a value that was previously yielded from a panic. Given that most panic values are strings, this is pretty unlikely. Regardless, undefined behavior
    // must be avoided. So we make one last desperate attempt at getting someone's attention, and then give up.
    let r = panic::catch_unwind(|| {
        log_handler_adapter_inner(opaque, level, file, line, area, message);
    });
    if let Err(e) = r {
        let cow_panic = panic_to_cow_str(e);
        let stderr_panic = if let Ok(cow_panic) = &cow_panic {
            panic::catch_unwind(|| {
                eprintln!("srt log handler panicked while panicking {cow_panic}");
            })
        } else {
            // At this point we have no way of knowing the type of `r`. If dropping `r` were to panic that would create undefined behavior.
            // We can't contain said panic, so instead we'll sidestep the possiblity of it ever happening by aborting.
            abort()
        };
        if stderr_panic.is_err() {
            // For similar reasons to the above, we must abort here.
            abort()
        }
    }
}

fn log_handler_adapter_inner(opaque: *mut c_void, level: c_int, file: *const c_char, line: c_int, area: *const c_char, message: *const c_char) {
    // The final panic layer is not very informative, so try and catch any panics possible here.
    let r = panic::catch_unwind(|| {
        let (closure, file_c_str, area_c_str, message_c_str) = unsafe {
            // opaque is already gated on a mutex by libsrt, so it's safe to mutate here.
            let closure = opaque as LogHandlerRaw;
            let file_c_str = cstr_to_cow_lossy(file);
            let area_c_str = cstr_to_cow_lossy(area);
            let message_c_str = cstr_to_cow_lossy(message);
            let closure = closure.as_mut().unwrap();
            // Spend as little time inside `unsafe` as possible, escalate these values back into a safe context.
            (closure, file_c_str, area_c_str, message_c_str)
        };
        (closure)(&SrtLogEvent {
            level: LogLevel::from_i32(level).unwrap_or(LogLevel::Error),
            file: file_c_str.as_deref(),
            line,
            area: area_c_str.as_deref(),
            message: message_c_str.as_deref(),
        });
    });
    if let Err(e) = r {
        // The two most common panic types are &str and String. Log those if possible.
        let cow_panic = panic_to_cow_str(e).ok();
        // eprintln can panic as well. Though this is unlikely.
        let _ = panic::catch_unwind(|| {
            // Because failing silently is considered a greater crime than using stderr from a library,
            // we will eprintln as a last resort.
            if let Some(s) = &cow_panic {
                eprintln!("srt log handler panicked: {s}");
            } else {
                eprintln!("srt log handler panicked, panic value was not &str or String.");
            }
        });
    }
}

fn panic_to_cow_str(e: Box<dyn Any + Send>) -> std::result::Result<Cow<'static, str>, Box<dyn Any + Send>> {
    e.downcast::<String>()
        .map(|b| *b)
        .map(Cow::Owned)
        .or_else(|e| e.downcast::<&str>().map(|b| *b).map(Cow::Borrowed))
}

/// Converts the given c string to a Cow<str> if possible. The given pointer must be either a valid string with a NUL terminator,
/// or null. Any other value is undefined behavior. The lifetime emitted here is speculative. It is on the caller to ensure the
/// lifetime is correct.
unsafe fn cstr_to_cow_lossy<'a>(c_str: *const c_char) -> Option<Cow<'a, str>> {
    if c_str.is_null() {
        return None;
    }
    // Some modification is acceptable as this is intended for human consumption.
    Some(CStr::from_ptr(c_str).to_string_lossy())
}

/// Sets the minimum severity for logging. A particular
/// log entry is displayed only if it has a severity greater than or equal to the minimum. Setting this to
/// [LogLevel::Debug] turns on all levels.
pub fn set_log_level(level: LogLevel) {
    unsafe { srt_setloglevel(level as c_int) }
}

#[repr(i32)]
#[derive(num_derive::FromPrimitive, num_derive::ToPrimitive)]
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
mod test {
    use super::*;
    use std::{
        convert::TryInto,
        net::UdpSocket,
        panic::panic_any,
        ptr::null_mut,
        sync::{
            atomic::{AtomicBool, AtomicU32, Ordering},
            mpsc, Arc, Mutex,
        },
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn test_client_server() {
        let (port_tx, port_rx) = mpsc::sync_channel(1);
        let server_thread = thread::spawn(move || {
            let listener = Listener::bind("127.0.0.1:0").unwrap();
            port_tx.send(listener.socket.socket_addr().unwrap().port()).unwrap();
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0; 1316];
            assert_eq!(conn.read(&mut buf).unwrap(), 3);
            assert_eq!(&buf[0..3], b"foo");

            assert!(conn.raw_stats(false, false).unwrap().pktRecvTotal > 0);
        });

        let port: u16 = port_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut conn = Stream::connect(format!("127.0.0.1:{port}"), &ConnectOptions::default()).unwrap();
        assert_eq!(conn.write(b"foo").unwrap(), 3);
        assert_eq!(conn.id(), None);

        server_thread.join().unwrap();
    }

    #[test]
    fn test_client_server_recovers_burst_loss_through_latency_proxy_matrix() {
        let scenarios = [
            SrtLossScenario {
                name: "keyframe-burst",
                payload_len: 40_000,
                drop_client_data_indices: contiguous_data_indices(3, 8),
            },
            SrtLossScenario {
                name: "keyframe-late-burst",
                payload_len: 64_000,
                drop_client_data_indices: contiguous_data_indices(19, 10),
            },
            SrtLossScenario {
                name: "delta-burst",
                payload_len: 18_000,
                drop_client_data_indices: contiguous_data_indices(4, 3),
            },
        ];

        for scenario in &scenarios {
            let result = run_srt_loss_scenario(scenario);

            assert_eq!(
                result.proxy_stats.dropped_client_data_packets,
                scenario.drop_client_data_indices.len(),
                "{} proxy drop count mismatch",
                scenario.name
            );
            assert!(
                result.proxy_stats.client_to_server_packets > result.proxy_stats.dropped_client_data_packets,
                "{} proxy should forward later client packets and SRT retransmissions",
                scenario.name
            );
            assert!(
                result.proxy_stats.server_to_client_packets > 0,
                "{} proxy should carry SRT handshake/feedback from server to client",
                scenario.name
            );
            assert!(
                result.client_stats.pktRetransTotal > 0 || result.client_stats.byteRetransTotal > 0,
                "{} SRT sender should retransmit dropped packets: {:?}",
                scenario.name,
                result.client_stats
            );
            assert!(
                result.server_stats.pktRcvLossTotal > 0 || result.server_stats.pktRcvRetrans > 0,
                "{} SRT receiver should observe loss or retransmitted packets: {:?}",
                scenario.name,
                result.server_stats
            );
            assert!(
                result.read_elapsed > Duration::from_millis(33),
                "{} SRT ARQ recovered the payload, but should miss a 33 ms video playout deadline over the simulated 70 ms RTT",
                scenario.name
            );
        }
    }

    #[test]
    fn test_client_server_recovers_sustained_video_stream_through_latency_proxy() {
        let scenario = SrtStreamScenario::video_scorecard();
        let result = run_srt_stream_scenario(&scenario);

        assert_eq!(result.frames_sent, 30);
        assert_eq!(result.frames_recovered, result.frames_sent);
        assert!(result.lost_frames >= 8, "SRT sustained stream should exercise repeated video-frame losses");
        assert_eq!(
            result.feedback_missed_frames, result.lost_frames,
            "every lost frame should miss the 33 ms low-latency deadline before SRT retransmission arrives"
        );
        assert_eq!(
            result.proxy_stats.dropped_client_data_packets, result.dropped_packets,
            "SRT sustained stream proxy drop count mismatch"
        );
        assert!(
            result.proxy_stats.client_to_server_packets > result.proxy_stats.dropped_client_data_packets,
            "proxy should forward later client packets and SRT retransmissions"
        );
        assert!(
            result.client_stats.pktRetransTotal > 0 || result.client_stats.byteRetransTotal > 0,
            "SRT sender should retransmit sustained stream packet losses: {:?}",
            result.client_stats
        );
        assert!(
            result.server_stats.pktRcvLossTotal > 0 || result.server_stats.pktRcvRetrans > 0,
            "SRT receiver should observe sustained stream loss or retransmits: {:?}",
            result.server_stats
        );
        assert!(
            result.read_elapsed > Duration::from_millis(33),
            "SRT sustained stream ARQ recovered the payload, but should miss a 33 ms video playout deadline over the simulated 70 ms RTT"
        );
    }

    #[test]
    fn test_passphrase() {
        let (port_tx, port_rx) = mpsc::sync_channel(1);
        let server_thread = thread::spawn(move || {
            let listener = Listener::bind_with_options("127.0.0.1:0", [ListenerOption::TooLatePacketDrop(false)].iter().cloned())
                .unwrap()
                .with_callback(|stream_id: Option<&_>| {
                    assert_eq!(stream_id, Some("mystreamid"));
                    ListenerCallbackAction::Allow {
                        passphrase: Some("thepassphrase".to_string()),
                    }
                })
                .unwrap();
            port_tx.send(listener.socket.socket_addr().unwrap().port()).unwrap();
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0; 1316];
            assert_eq!(conn.read(&mut buf).unwrap(), 3);
            assert_eq!(&buf[0..3], b"foo");
        });
        let port: u16 = port_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut options = ConnectOptions {
            stream_id: Some("mystreamid".to_string()),
            passphrase: Some("notthepassphrase".to_string()),
            max_send_payload_size: Some(1400),
            ..Default::default()
        };

        assert!(Stream::connect(format!("127.0.0.1:{port}"), &options).is_err());

        options.passphrase = Some("thepassphrase".to_string());
        let mut conn = Stream::connect(format!("127.0.0.1:{port}"), &options).unwrap();
        assert_eq!(conn.write(b"foo").unwrap(), 3);
        let buf = [0; 2000];
        assert_eq!(conn.write(&buf[..]).unwrap(), 1400);
        assert_eq!(conn.id(), options.stream_id.as_ref());

        server_thread.join().unwrap();
    }

    #[test]
    fn test_to_sockaddr() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let (sockaddr, socklen) = to_sockaddr(&addr);
        let round_tripped = sockaddr_from_storage(&sockaddr, socklen).unwrap();
        assert_eq!(addr, round_tripped);
    }

    #[derive(Debug, Clone)]
    struct SrtLossScenario {
        name: &'static str,
        payload_len: usize,
        drop_client_data_indices: Vec<usize>,
    }

    #[derive(Debug)]
    struct SrtLossScenarioResult {
        proxy_stats: SrtUdpProxyStats,
        client_stats: sys::SRT_TRACEBSTATS,
        server_stats: sys::SRT_TRACEBSTATS,
        read_elapsed: Duration,
    }

    #[derive(Debug, Clone)]
    struct SrtStreamFrame {
        payload_len: usize,
        drop_chunk_start: usize,
        drop_chunk_len: usize,
    }

    #[derive(Debug, Clone)]
    struct SrtStreamScenario {
        name: &'static str,
        frames: Vec<SrtStreamFrame>,
    }

    #[derive(Debug)]
    struct SrtStreamScenarioResult {
        proxy_stats: SrtUdpProxyStats,
        client_stats: sys::SRT_TRACEBSTATS,
        server_stats: sys::SRT_TRACEBSTATS,
        read_elapsed: Duration,
        frames_sent: usize,
        frames_recovered: usize,
        lost_frames: usize,
        feedback_missed_frames: usize,
        dropped_packets: usize,
    }

    impl SrtStreamScenario {
        fn video_scorecard() -> Self {
            let mut frames = Vec::new();
            for frame_index in 0..30 {
                if frame_index == 0 {
                    frames.push(SrtStreamFrame {
                        payload_len: 40_000,
                        drop_chunk_start: 3,
                        drop_chunk_len: 8,
                    });
                } else if frame_index % 9 == 0 {
                    frames.push(SrtStreamFrame {
                        payload_len: 18_000,
                        drop_chunk_start: 4,
                        drop_chunk_len: 3,
                    });
                } else if frame_index % 5 == 0 {
                    frames.push(SrtStreamFrame {
                        payload_len: 18_000,
                        drop_chunk_start: 5,
                        drop_chunk_len: 2,
                    });
                } else {
                    frames.push(SrtStreamFrame {
                        payload_len: 18_000,
                        drop_chunk_start: 0,
                        drop_chunk_len: 0,
                    });
                }
            }
            Self {
                name: "sustained-video-scorecard",
                frames,
            }
        }
    }

    fn run_srt_loss_scenario(scenario: &SrtLossScenario) -> SrtLossScenarioResult {
        let payload = video_like_payload(scenario.payload_len);
        let outcome = run_srt_payload_over_lossy_proxy(scenario.name, payload.clone(), scenario.drop_client_data_indices.clone());

        assert_eq!(outcome.received_payload, payload, "{} recovered payload mismatch", scenario.name);

        SrtLossScenarioResult {
            proxy_stats: outcome.proxy_stats,
            client_stats: outcome.client_stats,
            server_stats: outcome.server_stats,
            read_elapsed: outcome.read_elapsed,
        }
    }

    fn run_srt_stream_scenario(scenario: &SrtStreamScenario) -> SrtStreamScenarioResult {
        let mut payload = Vec::new();
        let mut expected_payloads = Vec::new();
        let mut drop_client_data_indices = Vec::new();
        let mut next_data_packet_index = 1usize;
        let mut lost_frames = 0usize;
        let mut feedback_missed_frames = 0usize;

        for (frame_index, frame) in scenario.frames.iter().enumerate() {
            let frame_payload = video_like_payload(frame.payload_len);
            let framed = frame_stream_record(frame_index as u32, &frame_payload);
            let chunk_count = framed.len().div_ceil(1316);
            let frame_drop_indices = if frame.drop_chunk_len == 0 {
                Vec::new()
            } else {
                let start = next_data_packet_index + frame.drop_chunk_start.saturating_sub(1);
                contiguous_data_indices(start, frame.drop_chunk_len)
            };
            if !frame_drop_indices.is_empty() {
                lost_frames += 1;
                if !feedback_only_can_recover_before_deadline(frame_drop_indices.len(), 70, 0, 33) {
                    feedback_missed_frames += 1;
                }
            }
            drop_client_data_indices.extend(frame_drop_indices);
            next_data_packet_index += chunk_count;
            payload.extend_from_slice(&framed);
            expected_payloads.push(frame_payload);
        }

        let outcome = run_srt_payload_over_lossy_proxy(scenario.name, payload.clone(), drop_client_data_indices.clone());
        assert_eq!(outcome.received_payload, payload, "{} recovered stream payload mismatch", scenario.name);
        let recovered_frames =
            decode_frame_stream(&outcome.received_payload).unwrap_or_else(|error| panic!("{} frame stream decode failed: {}", scenario.name, error));
        assert_eq!(recovered_frames, expected_payloads, "{} recovered frame payload mismatch", scenario.name);

        SrtStreamScenarioResult {
            proxy_stats: outcome.proxy_stats,
            client_stats: outcome.client_stats,
            server_stats: outcome.server_stats,
            read_elapsed: outcome.read_elapsed,
            frames_sent: scenario.frames.len(),
            frames_recovered: recovered_frames.len(),
            lost_frames,
            feedback_missed_frames,
            dropped_packets: drop_client_data_indices.len(),
        }
    }

    #[derive(Debug)]
    struct SrtPayloadOutcome {
        received_payload: Vec<u8>,
        proxy_stats: SrtUdpProxyStats,
        client_stats: sys::SRT_TRACEBSTATS,
        server_stats: sys::SRT_TRACEBSTATS,
        read_elapsed: Duration,
    }

    fn run_srt_payload_over_lossy_proxy(scenario_name: &str, payload: Vec<u8>, drop_client_data_indices: Vec<usize>) -> SrtPayloadOutcome {
        let expected_len = payload.len();
        let listener = Listener::bind_with_options(
            "127.0.0.1:0",
            [
                ListenerOption::TimestampBasedPacketDeliveryMode(false),
                ListenerOption::TooLatePacketDrop(false),
                ListenerOption::PeerLatency(120),
            ],
        )
        .unwrap_or_else(|error| panic!("{} bind listener failed: {}", scenario_name, error));
        listener
            .socket
            .set(sys::SRT_SOCKOPT_SRTO_RCVTIMEO, 8_000i32)
            .unwrap_or_else(|error| panic!("{} set listener timeout failed: {}", scenario_name, error));
        let server_addr = listener
            .socket
            .socket_addr()
            .unwrap_or_else(|error| panic!("{} listener socket addr failed: {}", scenario_name, error));
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{} bind proxy failed: {}", scenario_name, error));
        let proxy_addr = proxy_socket
            .local_addr()
            .unwrap_or_else(|error| panic!("{} proxy addr failed: {}", scenario_name, error));
        let stop_proxy = Arc::new(AtomicBool::new(false));
        let proxy_stats = Arc::new(Mutex::new(SrtUdpProxyStats::default()));
        let proxy_thread = spawn_lossy_srt_udp_proxy(
            proxy_socket,
            server_addr,
            Arc::clone(&stop_proxy),
            Arc::clone(&proxy_stats),
            SrtUdpProxyConfig {
                drop_client_data_indices,
                one_way_delay: Duration::from_millis(35),
            },
        );
        let (server_tx, server_rx) = mpsc::sync_channel(1);
        let server_thread = thread::spawn(move || {
            let result: std::result::Result<(Vec<u8>, sys::SRT_TRACEBSTATS, Duration), String> = (|| {
                let (mut conn, _) = listener.accept().map_err(|error| error.to_string())?;
                conn.socket.set(sys::SRT_SOCKOPT_SRTO_RCVTIMEO, 8_000i32).map_err(|error| error.to_string())?;

                let mut received = Vec::with_capacity(expected_len);
                let mut buf = [0_u8; 2048];
                let read_started = Instant::now();
                while received.len() < expected_len {
                    let len = conn.read(&mut buf).map_err(|error| error.to_string())?;
                    if len == 0 {
                        break;
                    }
                    received.extend_from_slice(&buf[..len]);
                }
                let elapsed = read_started.elapsed();
                let stats = conn.raw_stats(false, false).map_err(|error| error.to_string())?;
                Ok((received, stats, elapsed))
            })();
            server_tx.send(result).unwrap();
        });

        let mut conn = Stream::connect(
            proxy_addr,
            &ConnectOptions {
                timestamp_based_packet_delivery_mode: Some(false),
                too_late_packet_drop: Some(false),
                max_send_payload_size: Some(1316),
                ..Default::default()
            },
        )
        .unwrap_or_else(|error| panic!("{} connect through proxy failed: {}", scenario_name, error));
        conn.socket
            .set(sys::SRT_SOCKOPT_SRTO_SNDTIMEO, 8_000i32)
            .unwrap_or_else(|error| panic!("{} set send timeout failed: {}", scenario_name, error));
        for chunk in payload.chunks(1316) {
            conn.write_all(chunk)
                .unwrap_or_else(|error| panic!("{} write failed: {}", scenario_name, error));
        }

        let (received, server_stats, read_elapsed) = server_rx
            .recv_timeout(Duration::from_secs(12))
            .unwrap_or_else(|error| panic!("{} server timed out: {}", scenario_name, error))
            .unwrap_or_else(|error| panic!("{} server failed: {}", scenario_name, error));
        let client_stats = conn
            .raw_stats(false, false)
            .unwrap_or_else(|error| panic!("{} client stats failed: {}", scenario_name, error));

        stop_proxy.store(true, Ordering::SeqCst);
        proxy_thread.join().unwrap_or_else(|_| panic!("{} proxy thread panicked", scenario_name));
        server_thread.join().unwrap_or_else(|_| panic!("{} server thread panicked", scenario_name));
        let proxy_stats = proxy_stats.lock().unwrap().clone();

        SrtPayloadOutcome {
            received_payload: received,
            proxy_stats,
            client_stats,
            server_stats,
            read_elapsed,
        }
    }

    #[derive(Debug, Clone)]
    struct SrtUdpProxyConfig {
        drop_client_data_indices: Vec<usize>,
        one_way_delay: Duration,
    }

    #[derive(Debug, Default, Clone)]
    struct SrtUdpProxyStats {
        client_to_server_packets: usize,
        server_to_client_packets: usize,
        client_data_packets: usize,
        dropped_client_data_packets: usize,
    }

    fn spawn_lossy_srt_udp_proxy(
        socket: UdpSocket,
        server_addr: SocketAddr,
        stop: Arc<AtomicBool>,
        stats: Arc<Mutex<SrtUdpProxyStats>>,
        config: SrtUdpProxyConfig,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            socket.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
            let mut local_stats = SrtUdpProxyStats::default();
            let mut client_addr = None;
            let mut buf = [0_u8; 2048];

            while !stop.load(Ordering::SeqCst) {
                let (len, peer) = match socket.recv_from(&mut buf) {
                    Ok(packet) => packet,
                    Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                        continue;
                    }
                    Err(_) => break,
                };

                let from_server = peer == server_addr;
                let target = if from_server {
                    local_stats.server_to_client_packets += 1;
                    match client_addr {
                        Some(addr) => addr,
                        None => continue,
                    }
                } else {
                    local_stats.client_to_server_packets += 1;
                    if client_addr.is_none() {
                        client_addr = Some(peer);
                    }
                    server_addr
                };

                if !from_server && is_srt_data_packet(&buf[..len]) {
                    local_stats.client_data_packets += 1;
                    let data_index = local_stats.client_data_packets;
                    if config.drop_client_data_indices.contains(&data_index) {
                        local_stats.dropped_client_data_packets += 1;
                        continue;
                    }
                }

                forward_udp_packet_with_delay(&socket, target, buf[..len].to_vec(), config.one_way_delay);
            }

            *stats.lock().unwrap() = local_stats;
        })
    }

    fn is_srt_data_packet(packet: &[u8]) -> bool {
        packet.first().is_some_and(|first| first & 0x80 == 0)
    }

    fn forward_udp_packet_with_delay(socket: &UdpSocket, target: SocketAddr, packet: Vec<u8>, delay: Duration) {
        let socket = socket.try_clone().expect("clone UDP proxy socket");
        thread::spawn(move || {
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            let _ = socket.send_to(&packet, target);
        });
    }

    fn contiguous_data_indices(start: usize, len: usize) -> Vec<usize> {
        (start..start.saturating_add(len)).collect()
    }

    fn feedback_only_can_recover_before_deadline(lost_packets: usize, rtt_ms: u32, feedback_interval_ms: u32, frame_deadline_ms: u32) -> bool {
        lost_packets == 0 || rtt_ms.saturating_add(feedback_interval_ms) <= frame_deadline_ms
    }

    fn frame_stream_record(sequence: u32, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(12 + payload.len());
        record.extend_from_slice(b"SRTF");
        record.extend_from_slice(&sequence.to_le_bytes());
        record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn decode_frame_stream(bytes: &[u8]) -> std::result::Result<Vec<Vec<u8>>, String> {
        let mut frames = Vec::new();
        let mut cursor = 0usize;
        let mut expected_sequence = 0u32;

        while cursor < bytes.len() {
            if bytes.len() - cursor < 12 {
                return Err(format!("truncated frame header at byte {}", cursor));
            }
            if &bytes[cursor..cursor + 4] != b"SRTF" {
                return Err(format!("bad frame magic at byte {}", cursor));
            }

            let sequence = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
            if sequence != expected_sequence {
                return Err(format!("frame sequence {} arrived after {}", sequence, expected_sequence));
            }
            let payload_len = u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
            cursor += 12;

            let payload_end = cursor
                .checked_add(payload_len)
                .ok_or_else(|| format!("frame {} payload length overflow", sequence))?;
            if payload_end > bytes.len() {
                return Err(format!(
                    "frame {} payload truncated: need {} bytes, have {}",
                    sequence,
                    payload_len,
                    bytes.len().saturating_sub(cursor)
                ));
            }

            frames.push(bytes[cursor..payload_end].to_vec());
            cursor = payload_end;
            expected_sequence = expected_sequence.saturating_add(1);
        }

        Ok(frames)
    }

    fn video_like_payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| {
                let luma = index.wrapping_mul(37) ^ (index.rotate_left(3));
                let nal_hint = if index % 4096 == 0 { 0x65 } else { 0x41 };
                (luma as u8).wrapping_add(nal_hint)
            })
            .collect()
    }

    #[test]
    fn log_handler_doesnt_panic() {
        // If any panic unwinding moves past this point then undefined behavior would occur in real usage
        unsafe {
            log_handler_adapter(null_mut(), 0, null_mut(), 0, null_mut(), null_mut());
            log_handler_adapter(null_mut(), 0, b"file\0".as_ptr().cast::<c_char>(), 0, null_mut(), null_mut());
            log_handler_adapter(
                null_mut(),
                0,
                b"file\0".as_ptr().cast::<c_char>(),
                0,
                b"area\0".as_ptr().cast::<c_char>(),
                null_mut(),
            );
            log_handler_adapter(
                null_mut(),
                0,
                b"file\0".as_ptr().cast::<c_char>(),
                0,
                null_mut(),
                b"message\0".as_ptr().cast::<c_char>(),
            );
            log_handler_adapter(
                null_mut(),
                LOG_ERR,
                b"file\0".as_ptr().cast::<c_char>(),
                0,
                b"area\0".as_ptr().cast::<c_char>(),
                b"message\0".as_ptr().cast::<c_char>(),
            );
            {
                let log_handler: LogHandlerRaw = Box::into_raw(Box::new(Box::new(|_log_event| {
                    panic!();
                })));
                log_handler_adapter(log_handler.cast::<c_void>(), 0, null_mut(), 0, null_mut(), null_mut());
                log_handler_adapter(log_handler.cast::<c_void>(), 0, b"file\0".as_ptr().cast::<c_char>(), 0, null_mut(), null_mut());
                log_handler_adapter(
                    log_handler.cast::<c_void>(),
                    0,
                    b"file\0".as_ptr().cast::<c_char>(),
                    0,
                    b"area\0".as_ptr().cast::<c_char>(),
                    null_mut(),
                );
                log_handler_adapter(
                    log_handler.cast::<c_void>(),
                    0,
                    b"file\0".as_ptr().cast::<c_char>(),
                    0,
                    null_mut(),
                    b"message\0".as_ptr().cast::<c_char>(),
                );
                log_handler_adapter(
                    log_handler.cast::<c_void>(),
                    LOG_ERR,
                    b"file\0".as_ptr().cast::<c_char>(),
                    0,
                    b"area\0".as_ptr().cast::<c_char>(),
                    b"message\0".as_ptr().cast::<c_char>(),
                );
                let _ = Box::from_raw(log_handler);
            }
            {
                let called = Arc::new(AtomicU32::new(0));
                let called_clone = Arc::clone(&called);
                let log_handler: LogHandlerRaw = Box::into_raw(Box::new(Box::new(move |_log_event| {
                    // Record that this was called.
                    called.fetch_add(1, Ordering::Relaxed);
                })));
                log_handler_adapter(log_handler.cast::<c_void>(), 0, null_mut(), 0, null_mut(), null_mut());
                log_handler_adapter(log_handler.cast::<c_void>(), 0, b"file\0".as_ptr().cast::<c_char>(), 0, null_mut(), null_mut());
                log_handler_adapter(
                    log_handler.cast::<c_void>(),
                    0,
                    b"file\0".as_ptr().cast::<c_char>(),
                    0,
                    b"area\0".as_ptr().cast::<c_char>(),
                    null_mut(),
                );
                log_handler_adapter(
                    log_handler.cast::<c_void>(),
                    0,
                    b"file\0".as_ptr().cast::<c_char>(),
                    0,
                    null_mut(),
                    b"message\0".as_ptr().cast::<c_char>(),
                );
                log_handler_adapter(
                    log_handler.cast::<c_void>(),
                    LOG_ERR,
                    b"file\0".as_ptr().cast::<c_char>(),
                    0,
                    b"area\0".as_ptr().cast::<c_char>(),
                    b"message\0".as_ptr().cast::<c_char>(),
                );
                let _ = Box::from_raw(log_handler);
                assert_eq!(called_clone.load(Ordering::Relaxed), 5);
                assert_eq!(Arc::strong_count(&called_clone), 1);
            }
            {
                struct PanicBomb(Arc<AtomicU32>);
                impl Drop for PanicBomb {
                    fn drop(&mut self) {
                        self.0.fetch_add(1, Ordering::Relaxed);
                        panic!()
                    }
                }
                let drop_count = Arc::new(AtomicU32::new(0));
                let drop_count_clone = Arc::clone(&drop_count);
                let log_handler: LogHandlerRaw = Box::into_raw(Box::new(Box::new(move |_log_event| {
                    panic_any(PanicBomb(Arc::clone(&drop_count)));
                })));
                log_handler_adapter(log_handler.cast::<c_void>(), 0, null_mut(), 0, null_mut(), null_mut());
                log_handler_adapter(log_handler.cast::<c_void>(), 0, b"file\0".as_ptr().cast::<c_char>(), 0, null_mut(), null_mut());
                log_handler_adapter(
                    log_handler.cast::<c_void>(),
                    0,
                    b"file\0".as_ptr().cast::<c_char>(),
                    0,
                    b"area\0".as_ptr().cast::<c_char>(),
                    null_mut(),
                );
                log_handler_adapter(
                    log_handler.cast::<c_void>(),
                    0,
                    b"file\0".as_ptr().cast::<c_char>(),
                    0,
                    null_mut(),
                    b"message\0".as_ptr().cast::<c_char>(),
                );
                log_handler_adapter(
                    log_handler.cast::<c_void>(),
                    LOG_ERR,
                    b"file\0".as_ptr().cast::<c_char>(),
                    0,
                    b"area\0".as_ptr().cast::<c_char>(),
                    b"message\0".as_ptr().cast::<c_char>(),
                );
                let _ = Box::from_raw(log_handler);
                assert_eq!(drop_count_clone.load(Ordering::Relaxed), 5);
            }
        }
    }

    #[test]
    fn log_handler_used_correctly() {
        set_log_level(LogLevel::Debug);
        let called = Arc::new(AtomicU32::new(0));
        let called_clone = Arc::clone(&called);
        set_log_handler(move |_: &SrtLogEvent<'_>| {
            called.fetch_add(1, Ordering::Relaxed);
        });
        let (port_tx, port_rx) = mpsc::sync_channel(1);
        let server_thread = thread::spawn(move || {
            let listener = Listener::bind("127.0.0.1:0").unwrap();
            port_tx.send(listener.socket.socket_addr().unwrap().port()).unwrap();
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0; 1316];
            assert_eq!(conn.read(&mut buf).unwrap(), 3);
            assert_eq!(&buf[0..3], b"foo");

            assert!(conn.raw_stats(false, false).unwrap().pktRecvTotal > 0);
        });
        let port = port_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut conn = Stream::connect(format!("127.0.0.1:{port}"), &ConnectOptions::default()).unwrap();
        assert_eq!(conn.write(b"foo").unwrap(), 3);
        assert_eq!(conn.id(), None);

        server_thread.join().unwrap();
        let called_count = called_clone.load(Ordering::Relaxed);
        assert!(called_count > 0, "called_count = {}", called_count);
    }
}
