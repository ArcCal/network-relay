// Copied from masque-vpn's crates/masque-vpn/src/gssapi.rs; only the formatting differs.
//! The GSS-API method of SOCKS5 (RFC 1928 section 3, RFC 1961), as the proxy
//! side: security context establishment, protection-level subnegotiation and
//! per-message encapsulation of everything after them, TCP and UDP alike.
//!
//! The mechanism is behind [`Acceptor`] and [`Context`]. [`Kerberos`] is the
//! system's GSS-API library (RFC 2744 C bindings), loaded when first used:
//! MIT Kerberos's `libgssapi_krb5` on Linux and `GSS.framework` on macOS, so
//! nothing is linked, and needed, unless GSS-API is configured.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context as TaskContext, Poll, ready};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// The method number (RFC 1928 section 3).
pub const METHOD: u8 = 0x01;

/// Message header fields (RFC 1961 sections 3 to 5).
const VERSION: u8 = 1;
const AUTHENTICATION: u8 = 1;
const PROTECTION: u8 = 2;
const ENCAPSULATED: u8 = 3;
const ABORT: u8 = 0xff;
/// A token is at most this long: its length field has two octets.
pub const MAX_TOKEN: usize = u16::MAX as usize;
/// Rounds of context establishment a client may take; Kerberos takes one.
const MAX_ROUNDS: usize = 8;
/// Data per encapsulated TCP message: small enough to relay promptly.
const MAX_CHUNK: usize = 16 << 10;

/// Context flags (RFC 2744 section 3.9).
pub const CONF_FLAG: u32 = 16;
pub const INTEG_FLAG: u32 = 32;
/// Supplementary status bits of gss_unwrap: a token out of sequence.
const DUPLICATE_TOKEN: u32 = 1 << 1;
const OLD_TOKEN: u32 = 1 << 2;
const UNSEQ_TOKEN: u32 = 1 << 3;
const GAP_TOKEN: u32 = 1 << 4;

/// The protection agreed for everything after the subnegotiation (RFC 1961
/// section 4): every message is integrity-protected, and with
/// `Confidentiality` encrypted too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    Integrity = 1,
    Confidentiality = 2,
}

/// A GSS-API mechanism as acceptor.
pub trait Acceptor: Send + Sync {
    /// A new security context, for one client connection.
    fn context(&self) -> Result<Box<dyn Context>, String>;
    /// Whether the authenticated client may use the proxy.
    fn allows(&self, peer: &str) -> bool;
}

/// One client's security context.
pub trait Context: Send {
    /// One step of context establishment with the client's token: the token
    /// for the client (possibly empty), and whether the context is complete.
    fn accept(&mut self, token: &[u8]) -> Result<(Vec<u8>, bool), String>;
    /// The client's name, once the context is complete.
    fn peer(&self) -> String;
    /// The context's flags (CONF_FLAG, INTEG_FLAG and others).
    fn flags(&self) -> u32;
    fn wrap(&mut self, confidential: bool, data: &[u8]) -> Result<Vec<u8>, String>;
    /// The data, whether it was encrypted, and the supplementary status bits.
    fn unwrap(&mut self, token: &[u8]) -> Result<(Vec<u8>, bool, u32), String>;
    /// The most data whose token is at most `max_token` long.
    fn max_input(&mut self, confidential: bool, max_token: usize) -> Result<usize, String>;
}

/// A context shared by a connection's stream and its UDP association.
pub type Shared = Arc<Mutex<Box<dyn Context>>>;

fn invalid(why: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.into())
}

fn message(mtyp: u8, token: &[u8]) -> io::Result<Vec<u8>> {
    let len = u16::try_from(token.len()).map_err(|_| invalid("GSS-API token too long"))?;
    let mut m = Vec::with_capacity(4 + token.len());
    m.extend_from_slice(&[VERSION, mtyp]);
    m.extend_from_slice(&len.to_be_bytes());
    m.extend_from_slice(token);
    Ok(m)
}

/// Reads one message: its type and token. An abort message has no token.
async fn read_message<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(invalid(format!("GSS-API message version {}", head[0])));
    }
    if head[1] == ABORT {
        return Ok((ABORT, Vec::new()));
    }
    let mut token = vec![0; s.read_u16().await?.into()];
    s.read_exact(&mut token).await?;
    Ok((head[1], token))
}

/// Ends context establishment: the client is told with an abort message
/// (RFC 1961 section 3.8) and the connection is closed.
async fn abort<S: AsyncWrite + Unpin>(s: &mut S, why: String) -> io::Error {
    let _ = s.write_all(&[VERSION, ABORT]).await;
    io::Error::new(io::ErrorKind::PermissionDenied, why)
}

/// After the client chose the method: context establishment (RFC 1961
/// section 3) and protection-level subnegotiation (section 4). Returns the
/// context, the protection agreed, and the client's name.
pub async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    acceptor: &dyn Acceptor,
) -> io::Result<(Box<dyn Context>, Protection, String)> {
    let mut context = match acceptor.context() {
        Ok(c) => c,
        Err(e) => return Err(abort(s, e).await),
    };
    for round in 1.. {
        let (mtyp, token) = read_message(s).await?;
        match mtyp {
            AUTHENTICATION if round <= MAX_ROUNDS => {}
            ABORT => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "the client aborted",
                ));
            }
            AUTHENTICATION => return Err(abort(s, "too many GSS-API rounds".into()).await),
            other => {
                return Err(abort(
                    s,
                    format!("GSS-API message type {other} during authentication"),
                )
                .await);
            }
        }
        match context.accept(&token) {
            // With nothing to send, a zero-length token says the server is
            // ready (section 3.6).
            Ok((reply, complete)) => {
                s.write_all(&message(AUTHENTICATION, &reply)?).await?;
                if complete {
                    break;
                }
            }
            Err(e) => return Err(abort(s, e).await),
        }
    }
    let peer = context.peer();
    if !acceptor.allows(&peer) {
        return Err(abort(s, format!("{peer} may not use the proxy")).await);
    }
    if context.flags() & INTEG_FLAG == 0 {
        return Err(abort(s, "the context offers no integrity protection".into()).await);
    }

    // The client's required level, wrapped without confidentiality; the
    // server answers with the level it agrees to (section 4.3, 4.4).
    let (mtyp, token) = read_message(s).await?;
    if mtyp != PROTECTION {
        return Err(invalid(format!(
            "GSS-API message type {mtyp} instead of a protection level"
        )));
    }
    let (level, _, _) = context.unwrap(&token).map_err(invalid)?;
    let confidentiality = context.flags() & CONF_FLAG != 0;
    let protection = match level[..] {
        [1] => Protection::Integrity,
        // Selective protection (3) is agreed as the stronger of the two.
        [2] | [3] if confidentiality => Protection::Confidentiality,
        [2] | [3] => Protection::Integrity,
        _ => return Err(invalid(format!("GSS-API protection level {level:?}"))),
    };
    let reply = context.wrap(false, &[protection as u8]).map_err(invalid)?;
    s.write_all(&message(PROTECTION, &reply)?).await?;
    Ok((context, protection, peer))
}

/// Unwraps an encapsulated message's token: the data if its protection is
/// the agreed one. `stream` rejects tokens out of sequence too.
fn open(
    context: &Shared,
    protection: Protection,
    token: &[u8],
    stream: bool,
) -> io::Result<Vec<u8>> {
    let mut context = context.lock().unwrap_or_else(|e| e.into_inner());
    let (data, confidential, supplementary) = context.unwrap(token).map_err(invalid)?;
    if protection == Protection::Confidentiality && !confidential {
        return Err(invalid(
            "an unencrypted GSS-API message where encryption was agreed",
        ));
    }
    let out_of_sequence = if stream {
        DUPLICATE_TOKEN | OLD_TOKEN | UNSEQ_TOKEN | GAP_TOKEN
    } else {
        DUPLICATE_TOKEN
    };
    if supplementary & out_of_sequence != 0 {
        return Err(invalid("a GSS-API message out of sequence"));
    }
    Ok(data)
}

fn seal(context: &Shared, protection: Protection, data: &[u8]) -> io::Result<Vec<u8>> {
    let mut context = context.lock().unwrap_or_else(|e| e.into_inner());
    let token = context
        .wrap(protection == Protection::Confidentiality, data)
        .map_err(invalid)?;
    message(ENCAPSULATED, &token)
}

/// A client's UDP datagram: the SOCKS UDP request it encapsulates (RFC 1961
/// section 5), or `None` for one to drop.
pub fn open_datagram(context: &Shared, protection: Protection, datagram: &[u8]) -> Option<Vec<u8>> {
    let (&[VERSION, ENCAPSULATED, hi, lo], token) = datagram.split_first_chunk::<4>()? else {
        return None;
    };
    if token.len() != usize::from(u16::from_be_bytes([hi, lo])) {
        return None;
    }
    open(context, protection, token, false).ok()
}

/// A UDP datagram for the client, encapsulating `packet`; `None` if it
/// would not fit in one.
pub fn seal_datagram(context: &Shared, protection: Protection, packet: &[u8]) -> Option<Vec<u8>> {
    seal(context, protection, packet)
        .ok()
        .filter(|d| d.len() <= 65_507)
}

/// A client connection after authentication: everything read and written is
/// encapsulated in GSS-API messages (RFC 1961 section 5).
pub struct Stream<S> {
    inner: S,
    context: Shared,
    protection: Protection,
    max_chunk: usize,
    /// A message being read: its header and token so far.
    incoming: Vec<u8>,
    /// Unwrapped data not yet read, from `taken` on.
    data: Vec<u8>,
    taken: usize,
    /// Messages not yet written, from `sent` on.
    outgoing: Vec<u8>,
    sent: usize,
}

impl<S> Stream<S> {
    pub fn new(inner: S, context: Box<dyn Context>, protection: Protection) -> io::Result<Self> {
        let mut context = context;
        let confidential = protection == Protection::Confidentiality;
        let max_chunk = context
            .max_input(confidential, MAX_TOKEN)
            .map_err(invalid)?
            .min(MAX_CHUNK);
        if max_chunk == 0 {
            return Err(invalid("GSS-API tokens cannot carry data"));
        }
        Ok(Self {
            inner,
            context: Arc::new(Mutex::new(context)),
            protection,
            max_chunk,
            incoming: Vec::new(),
            data: Vec::new(),
            taken: 0,
            outgoing: Vec::new(),
            sent: 0,
        })
    }

    /// The security context and protection, for the connection's UDP
    /// association.
    pub fn security(&self) -> (Shared, Protection) {
        (self.context.clone(), self.protection)
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncWrite + Unpin> Stream<S> {
    /// Writes out what is buffered.
    fn poll_drain(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while self.sent < self.outgoing.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.outgoing[self.sent..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sent += n;
        }
        self.outgoing.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.taken == this.data.len() {
            // The header, then the token its length names.
            if this.incoming.len() >= 2 && this.incoming[..2] != [VERSION, ENCAPSULATED] {
                return Poll::Ready(Err(invalid(format!(
                    "GSS-API message {:?}",
                    &this.incoming[..2]
                ))));
            }
            let want = match this.incoming[..] {
                [_, _, hi, lo, ..] => 4 + usize::from(u16::from_be_bytes([hi, lo])),
                _ => 4,
            };
            if want == 4 && this.incoming.len() == 4 {
                return Poll::Ready(Err(invalid("an empty GSS-API token")));
            }
            if this.incoming.len() == want {
                let token = std::mem::take(&mut this.incoming);
                this.data = open(&this.context, this.protection, &token[4..], true)?;
                this.taken = 0;
                continue;
            }
            let mut chunk = vec![0; want - this.incoming.len()];
            let mut read = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                return Poll::Ready(if this.incoming.is_empty() {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "a GSS-API message cut short",
                    ))
                });
            }
            this.incoming.extend_from_slice(read.filled());
        }
        let n = buf.remaining().min(this.data.len() - this.taken);
        buf.put_slice(&this.data[this.taken..this.taken + n]);
        this.taken += n;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(this.max_chunk);
        this.outgoing = seal(&this.context, this.protection, &buf[..n])?;
        this.sent = 0;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

// ------------------------------------------------------------ the system library

type Status = u32;
type Handle = *mut c_void;

#[repr(C)]
struct Buffer {
    length: usize,
    value: *mut c_void,
}

impl Buffer {
    fn empty() -> Self {
        Self {
            length: 0,
            value: std::ptr::null_mut(),
        }
    }

    fn input(data: &[u8]) -> Self {
        Self {
            length: data.len(),
            value: data.as_ptr() as *mut c_void,
        }
    }
}

const NO_HANDLE: Handle = std::ptr::null_mut();
const GSS_CODE: c_int = 1;
const MECH_CODE: c_int = 2;
const ACCEPT: c_int = 2;
const INDEFINITE: u32 = u32::MAX;
const CONTINUE_NEEDED: Status = 1;
/// Calling and routine errors; the low bits are supplementary information.
const ERROR_MASK: Status = 0xffff_0000;

type AcquireCred = unsafe extern "C" fn(
    *mut u32,
    Handle,
    u32,
    Handle,
    c_int,
    *mut Handle,
    *mut Handle,
    *mut u32,
) -> Status;
type AcceptSecContext = unsafe extern "C" fn(
    *mut u32,
    *mut Handle,
    Handle,
    *mut Buffer,
    Handle,
    *mut Handle,
    *mut Handle,
    *mut Buffer,
    *mut u32,
    *mut u32,
    *mut Handle,
) -> Status;
type InitSecContext = unsafe extern "C" fn(
    *mut u32,
    Handle,
    *mut Handle,
    Handle,
    Handle,
    u32,
    u32,
    Handle,
    *mut Buffer,
    *mut Handle,
    *mut Buffer,
    *mut u32,
    *mut u32,
) -> Status;
type ImportName = unsafe extern "C" fn(*mut u32, *mut Buffer, Handle, *mut Handle) -> Status;
type DisplayName = unsafe extern "C" fn(*mut u32, Handle, *mut Buffer, *mut Handle) -> Status;
type Wrap = unsafe extern "C" fn(
    *mut u32,
    Handle,
    c_int,
    u32,
    *mut Buffer,
    *mut c_int,
    *mut Buffer,
) -> Status;
type Unwrap = unsafe extern "C" fn(
    *mut u32,
    Handle,
    *mut Buffer,
    *mut Buffer,
    *mut c_int,
    *mut u32,
) -> Status;
type WrapSizeLimit = unsafe extern "C" fn(*mut u32, Handle, c_int, u32, u32, *mut u32) -> Status;
type ReleaseBuffer = unsafe extern "C" fn(*mut u32, *mut Buffer) -> Status;
type ReleaseHandle = unsafe extern "C" fn(*mut u32, *mut Handle) -> Status;
type DeleteSecContext = unsafe extern "C" fn(*mut u32, *mut Handle, *mut Buffer) -> Status;
type DisplayStatus =
    unsafe extern "C" fn(*mut u32, u32, c_int, Handle, *mut u32, *mut Buffer) -> Status;
type RegisterAcceptorIdentity = unsafe extern "C" fn(*const c_char) -> Status;

/// The system's GSS-API functions.
struct Library {
    acquire_cred: AcquireCred,
    accept_sec_context: AcceptSecContext,
    init_sec_context: InitSecContext,
    import_name: ImportName,
    display_name: DisplayName,
    wrap: Wrap,
    unwrap: Unwrap,
    wrap_size_limit: WrapSizeLimit,
    release_buffer: ReleaseBuffer,
    release_name: ReleaseHandle,
    release_cred: ReleaseHandle,
    delete_sec_context: DeleteSecContext,
    display_status: DisplayStatus,
    register_acceptor_identity: RegisterAcceptorIdentity,
    /// GSS_C_NT_HOSTBASED_SERVICE, for initiators.
    hostbased_service: Handle,
}

// SAFETY: function pointers, and the address of a constant OID.
unsafe impl Send for Library {}
unsafe impl Sync for Library {}

#[cfg(target_os = "macos")]
const LIBRARY: &str = "/System/Library/Frameworks/GSS.framework/GSS";
#[cfg(not(target_os = "macos"))]
const LIBRARY: &str = "libgssapi_krb5.so.2";
#[cfg(target_os = "macos")]
const REGISTER_ACCEPTOR_IDENTITY: &str = "gsskrb5_register_acceptor_identity";
#[cfg(not(target_os = "macos"))]
const REGISTER_ACCEPTOR_IDENTITY: &str = "krb5_gss_register_acceptor_identity";

// The dynamic loader (POSIX); in the C library, or libdl, which Rust's
// standard library links on glibc.
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    #[link_name = "dlerror"]
    fn dl_error() -> *const c_char;
}
const RTLD_NOW: c_int = 2;
#[cfg(target_os = "macos")]
const RTLD_LOCAL: c_int = 4;
#[cfg(not(target_os = "macos"))]
const RTLD_LOCAL: c_int = 0;

fn dlerror() -> String {
    // SAFETY: dlerror returns null or a C string valid until the next call.
    let e = unsafe { dl_error() };
    if e.is_null() {
        "unknown error".into()
    } else {
        // SAFETY: as above.
        unsafe { CStr::from_ptr(e) }.to_string_lossy().into_owned()
    }
}

fn library() -> Result<&'static Library, String> {
    static LOADED: OnceLock<Result<Library, String>> = OnceLock::new();
    LOADED.get_or_init(load).as_ref().map_err(Clone::clone)
}

fn load() -> Result<Library, String> {
    let path = CString::new(LIBRARY).expect("no NUL");
    // SAFETY: loading a system library; it is never unloaded.
    let handle = unsafe { dlopen(path.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
    if handle.is_null() {
        return Err(format!(
            "loading the GSS-API library {LIBRARY}: {}",
            dlerror()
        ));
    }
    let symbol = |name: &str| -> Result<*mut c_void, String> {
        let c = CString::new(name).expect("no NUL");
        // SAFETY: a symbol lookup in a library that stays loaded.
        let p = unsafe { dlsym(handle, c.as_ptr()) };
        if p.is_null() {
            Err(format!("{LIBRARY} has no {name}"))
        } else {
            Ok(p)
        }
    };
    macro_rules! function {
        ($name:expr, $type:ty) => {
            // SAFETY: the symbol is the RFC 2744 function of this type.
            unsafe { std::mem::transmute::<*mut c_void, $type>(symbol($name)?) }
        };
    }
    // MIT exports GSS_C_NT_HOSTBASED_SERVICE as a variable holding the OID's
    // address; GSS.framework exports the OID itself.
    #[cfg(target_os = "macos")]
    let hostbased_service = symbol("__gss_c_nt_hostbased_service_oid_desc")?;
    #[cfg(not(target_os = "macos"))]
    // SAFETY: the variable holds a gss_OID.
    let hostbased_service = unsafe { *(symbol("GSS_C_NT_HOSTBASED_SERVICE")? as *const Handle) };
    Ok(Library {
        acquire_cred: function!("gss_acquire_cred", AcquireCred),
        accept_sec_context: function!("gss_accept_sec_context", AcceptSecContext),
        init_sec_context: function!("gss_init_sec_context", InitSecContext),
        import_name: function!("gss_import_name", ImportName),
        display_name: function!("gss_display_name", DisplayName),
        wrap: function!("gss_wrap", Wrap),
        unwrap: function!("gss_unwrap", Unwrap),
        wrap_size_limit: function!("gss_wrap_size_limit", WrapSizeLimit),
        release_buffer: function!("gss_release_buffer", ReleaseBuffer),
        release_name: function!("gss_release_name", ReleaseHandle),
        release_cred: function!("gss_release_cred", ReleaseHandle),
        delete_sec_context: function!("gss_delete_sec_context", DeleteSecContext),
        display_status: function!("gss_display_status", DisplayStatus),
        register_acceptor_identity: function!(REGISTER_ACCEPTOR_IDENTITY, RegisterAcceptorIdentity),
        hostbased_service,
    })
}

impl Library {
    /// Takes a buffer the library allocated.
    fn take(&self, buffer: &mut Buffer) -> Vec<u8> {
        let data = if buffer.length == 0 || buffer.value.is_null() {
            Vec::new()
        } else {
            // SAFETY: the library filled `length` bytes at `value`.
            unsafe { std::slice::from_raw_parts(buffer.value as *const u8, buffer.length) }.to_vec()
        };
        let mut minor = 0;
        // SAFETY: releasing the library's own buffer once.
        unsafe { (self.release_buffer)(&mut minor, buffer) };
        data
    }

    /// The messages for a failed call.
    fn error(&self, call: &str, major: Status, minor: u32) -> String {
        let mut messages = Vec::new();
        for (code, kind) in [(major, GSS_CODE), (minor, MECH_CODE)] {
            if code == 0 {
                continue;
            }
            let mut context = 0;
            loop {
                let (mut m, mut text) = (0, Buffer::empty());
                // SAFETY: an output buffer for the library to fill.
                let status = unsafe {
                    (self.display_status)(&mut m, code, kind, NO_HANDLE, &mut context, &mut text)
                };
                if status & ERROR_MASK != 0 {
                    break;
                }
                messages.push(String::from_utf8_lossy(&self.take(&mut text)).into_owned());
                if context == 0 {
                    break;
                }
            }
        }
        format!("{call}: {}", messages.join("; "))
    }

    fn display_name(&self, name: Handle) -> String {
        let (mut minor, mut text) = (0, Buffer::empty());
        // SAFETY: a name from the library, and an output buffer.
        let major =
            unsafe { (self.display_name)(&mut minor, name, &mut text, std::ptr::null_mut()) };
        if major & ERROR_MASK != 0 {
            return String::new();
        }
        String::from_utf8_lossy(&self.take(&mut text)).into_owned()
    }
}

/// Kerberos (or another mechanism of the system's GSS-API library) as
/// acceptor, with the keys of a keytab.
pub struct Kerberos {
    lib: &'static Library,
    credential: Handle,
    /// Client principals allowed; empty for any the keytab's realm vouches for.
    principals: Vec<String>,
}

// SAFETY: a credential handle is used only to accept contexts, which the
// library allows from any thread.
unsafe impl Send for Kerberos {}
unsafe impl Sync for Kerberos {}

impl Kerberos {
    /// Loads the library and the acceptor credentials of `keytab`.
    pub fn new(keytab: &Path, principals: Vec<String>) -> Result<Self, String> {
        let lib = library()?;
        std::fs::File::open(keytab)
            .map_err(|e| format!("GSS-API keytab {}: {e}", keytab.display()))?;
        let path = CString::new(keytab.as_os_str().as_encoded_bytes())
            .map_err(|_| format!("GSS-API keytab {}: a NUL in the path", keytab.display()))?;
        // SAFETY: a C string, copied by the library.
        let major = unsafe { (lib.register_acceptor_identity)(path.as_ptr()) };
        if major & ERROR_MASK != 0 {
            return Err(lib.error("registering the keytab", major, 0));
        }
        let (mut minor, mut credential) = (0, NO_HANDLE);
        // SAFETY: default name and mechanisms; an output handle.
        let major = unsafe {
            (lib.acquire_cred)(
                &mut minor,
                NO_HANDLE,
                INDEFINITE,
                NO_HANDLE,
                ACCEPT,
                &mut credential,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if major & ERROR_MASK != 0 {
            return Err(lib.error(
                &format!("GSS-API acceptor credentials from {}", keytab.display()),
                major,
                minor,
            ));
        }
        Ok(Self {
            lib,
            credential,
            principals,
        })
    }
}

impl Drop for Kerberos {
    fn drop(&mut self) {
        let mut minor = 0;
        // SAFETY: the credential is released once.
        unsafe { (self.lib.release_cred)(&mut minor, &mut self.credential) };
    }
}

impl Acceptor for Kerberos {
    fn context(&self) -> Result<Box<dyn Context>, String> {
        Ok(Box::new(SystemContext {
            lib: self.lib,
            credential: self.credential,
            handle: NO_HANDLE,
            flags: 0,
            peer: String::new(),
        }))
    }

    fn allows(&self, peer: &str) -> bool {
        self.principals.is_empty() || self.principals.iter().any(|p| p == peer)
    }
}

/// A context of the system library, as acceptor or initiator.
struct SystemContext {
    lib: &'static Library,
    /// The acceptor's credential, borrowed from [`Kerberos`], which outlives
    /// the proxy; none for an initiator.
    credential: Handle,
    handle: Handle,
    flags: u32,
    peer: String,
}

// SAFETY: a context is used by one thread at a time (behind a Mutex where
// shared), which the library allows.
unsafe impl Send for SystemContext {}

impl Drop for SystemContext {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let mut minor = 0;
            // SAFETY: the context is deleted once; no token is produced
            // (RFC 1961 section 6).
            unsafe {
                (self.lib.delete_sec_context)(&mut minor, &mut self.handle, std::ptr::null_mut())
            };
        }
    }
}

impl Context for SystemContext {
    fn accept(&mut self, token: &[u8]) -> Result<(Vec<u8>, bool), String> {
        let lib = self.lib;
        let (mut minor, mut input, mut output, mut name) =
            (0, Buffer::input(token), Buffer::empty(), NO_HANDLE);
        // SAFETY: the input outlives the call; outputs are the library's.
        let major = unsafe {
            (lib.accept_sec_context)(
                &mut minor,
                &mut self.handle,
                self.credential,
                &mut input,
                NO_HANDLE,
                &mut name,
                std::ptr::null_mut(),
                &mut output,
                &mut self.flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let reply = lib.take(&mut output);
        if !name.is_null() {
            self.peer = lib.display_name(name);
            // SAFETY: the name is released once.
            unsafe { (lib.release_name)(&mut 0, &mut name) };
        }
        if major & ERROR_MASK != 0 {
            return Err(lib.error("gss_accept_sec_context", major, minor));
        }
        Ok((reply, major & CONTINUE_NEEDED == 0))
    }

    fn peer(&self) -> String {
        self.peer.clone()
    }

    fn flags(&self) -> u32 {
        self.flags
    }

    fn wrap(&mut self, confidential: bool, data: &[u8]) -> Result<Vec<u8>, String> {
        let lib = self.lib;
        let (mut minor, mut input, mut output, mut applied) =
            (0, Buffer::input(data), Buffer::empty(), 0);
        // SAFETY: as in `accept`.
        let major = unsafe {
            (lib.wrap)(
                &mut minor,
                self.handle,
                c_int::from(confidential),
                0,
                &mut input,
                &mut applied,
                &mut output,
            )
        };
        let token = lib.take(&mut output);
        if major & ERROR_MASK != 0 {
            return Err(lib.error("gss_wrap", major, minor));
        }
        if confidential && applied == 0 {
            return Err("gss_wrap: no confidentiality".into());
        }
        Ok(token)
    }

    fn unwrap(&mut self, token: &[u8]) -> Result<(Vec<u8>, bool, u32), String> {
        let lib = self.lib;
        let (mut minor, mut input, mut output, mut confidential, mut qop) =
            (0, Buffer::input(token), Buffer::empty(), 0, 0);
        // SAFETY: as in `accept`.
        let major = unsafe {
            (lib.unwrap)(
                &mut minor,
                self.handle,
                &mut input,
                &mut output,
                &mut confidential,
                &mut qop,
            )
        };
        let data = lib.take(&mut output);
        if major & ERROR_MASK != 0 {
            return Err(lib.error("gss_unwrap", major, minor));
        }
        Ok((data, confidential != 0, major & !ERROR_MASK))
    }

    fn max_input(&mut self, confidential: bool, max_token: usize) -> Result<usize, String> {
        let (mut minor, mut max) = (0, 0);
        let limit = u32::try_from(max_token).unwrap_or(u32::MAX);
        // SAFETY: an output integer.
        let major = unsafe {
            (self.lib.wrap_size_limit)(
                &mut minor,
                self.handle,
                c_int::from(confidential),
                0,
                limit,
                &mut max,
            )
        };
        if major & ERROR_MASK != 0 {
            return Err(self.lib.error("gss_wrap_size_limit", major, minor));
        }
        Ok(max as usize)
    }
}

/// The client side, for tests and tools: a context with `service@host`
/// (GSS_C_NT_HOSTBASED_SERVICE) using the default credentials.
pub struct Initiator {
    context: SystemContext,
    target: Handle,
    /// Flags requested: mutual authentication, replay and sequence
    /// detection, integrity and confidentiality.
    requested: u32,
}

// SAFETY: as for SystemContext; the name is used only with the context.
unsafe impl Send for Initiator {}

impl Initiator {
    pub fn new(service: &str) -> Result<Self, String> {
        let lib = library()?;
        let (mut minor, mut target) = (0, NO_HANDLE);
        let mut name = Buffer::input(service.as_bytes());
        // SAFETY: the name is copied by the library.
        let major =
            unsafe { (lib.import_name)(&mut minor, &mut name, lib.hostbased_service, &mut target) };
        if major & ERROR_MASK != 0 {
            return Err(lib.error("gss_import_name", major, minor));
        }
        Ok(Self {
            context: SystemContext {
                lib,
                credential: NO_HANDLE,
                handle: NO_HANDLE,
                flags: 0,
                peer: String::new(),
            },
            target,
            requested: 2 | 4 | 8 | CONF_FLAG | INTEG_FLAG,
        })
    }

    /// One step: the token for the server, and whether the context is
    /// complete. The first step has no input.
    pub fn step(&mut self, input: Option<&[u8]>) -> Result<(Vec<u8>, bool), String> {
        let lib = self.context.lib;
        let mut buffer = input.map(Buffer::input);
        let input = buffer
            .as_mut()
            .map_or(std::ptr::null_mut(), |b| b as *mut Buffer);
        let (mut minor, mut output) = (0, Buffer::empty());
        // SAFETY: as in `accept`; null input on the first call.
        let major = unsafe {
            (lib.init_sec_context)(
                &mut minor,
                NO_HANDLE,
                &mut self.context.handle,
                self.target,
                NO_HANDLE,
                self.requested,
                0,
                NO_HANDLE,
                input,
                std::ptr::null_mut(),
                &mut output,
                &mut self.context.flags,
                std::ptr::null_mut(),
            )
        };
        let token = lib.take(&mut output);
        if major & ERROR_MASK != 0 {
            return Err(lib.error("gss_init_sec_context", major, minor));
        }
        Ok((token, major & CONTINUE_NEEDED == 0))
    }

    pub fn wrap(&mut self, confidential: bool, data: &[u8]) -> Result<Vec<u8>, String> {
        self.context.wrap(confidential, data)
    }

    pub fn unwrap(&mut self, token: &[u8]) -> Result<(Vec<u8>, bool, u32), String> {
        self.context.unwrap(token)
    }
}

impl Drop for Initiator {
    fn drop(&mut self) {
        // SAFETY: the name is released once.
        unsafe { (self.context.lib.release_name)(&mut 0, &mut self.target) };
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A stand-in mechanism: the client's token "hello" completes the
    /// context with the reply "welcome"; wrapping prefixes a byte saying
    /// whether the data is "encrypted" (inverted) and a sequence number.
    #[derive(Clone)]
    pub(crate) struct Toy {
        pub(crate) flags: u32,
        pub(crate) peer: &'static str,
        pub(crate) rounds: usize,
        /// The number of its contexts not yet dropped.
        pub(crate) live: Arc<AtomicUsize>,
    }

    impl Toy {
        pub(crate) fn new(flags: u32, rounds: usize) -> Self {
            Self {
                flags,
                peer: "alice@TEST",
                rounds,
                live: Arc::default(),
            }
        }
    }

    pub(crate) struct ToyContext {
        flags: u32,
        peer: &'static str,
        rounds: usize,
        sent: u8,
        received: u8,
        live: Arc<AtomicUsize>,
    }

    impl Drop for ToyContext {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl Acceptor for Toy {
        fn context(&self) -> Result<Box<dyn Context>, String> {
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(ToyContext {
                flags: self.flags,
                peer: self.peer,
                rounds: self.rounds,
                sent: 0,
                received: 0,
                live: self.live.clone(),
            }))
        }

        fn allows(&self, peer: &str) -> bool {
            peer != "mallory@TEST"
        }
    }

    impl Context for ToyContext {
        fn accept(&mut self, token: &[u8]) -> Result<(Vec<u8>, bool), String> {
            match token {
                b"hello" if self.rounds > 1 => {
                    self.rounds -= 1;
                    Ok((b"again".to_vec(), false))
                }
                b"hello" => Ok((b"welcome".to_vec(), true)),
                _ => Err("bad token".into()),
            }
        }

        fn peer(&self) -> String {
            self.peer.into()
        }

        fn flags(&self) -> u32 {
            self.flags
        }

        fn wrap(&mut self, confidential: bool, data: &[u8]) -> Result<Vec<u8>, String> {
            self.sent = self.sent.wrapping_add(1);
            let mut t = vec![u8::from(confidential), self.sent];
            t.extend(data.iter().map(|b| if confidential { !b } else { *b }));
            Ok(t)
        }

        fn unwrap(&mut self, token: &[u8]) -> Result<(Vec<u8>, bool, u32), String> {
            let [conf, seq, data @ ..] = token else {
                return Err("short token".into());
            };
            let expected = self.received.wrapping_add(1);
            let supplementary = if *seq == expected {
                0
            } else if *seq < expected {
                DUPLICATE_TOKEN
            } else {
                GAP_TOKEN
            };
            self.received = self.received.max(*seq);
            let confidential = *conf == 1;
            Ok((
                data.iter()
                    .map(|b| if confidential { !b } else { *b })
                    .collect(),
                confidential,
                supplementary,
            ))
        }

        fn max_input(&mut self, _: bool, max_token: usize) -> Result<usize, String> {
            Ok(max_token - 2)
        }
    }

    /// The client's half of the toy mechanism.
    pub(crate) struct ToyClient {
        sent: u8,
        received: u8,
    }

    impl ToyClient {
        pub(crate) fn new() -> Self {
            Self {
                sent: 0,
                received: 0,
            }
        }

        pub(crate) fn wrap(&mut self, confidential: bool, data: &[u8]) -> Vec<u8> {
            self.sent = self.sent.wrapping_add(1);
            let mut t = vec![u8::from(confidential), self.sent];
            t.extend(data.iter().map(|b| if confidential { !b } else { *b }));
            t
        }

        pub(crate) fn unwrap(&mut self, token: &[u8]) -> (Vec<u8>, bool) {
            let [conf, seq, data @ ..] = token else {
                panic!("short token")
            };
            assert_eq!(*seq, self.received.wrapping_add(1), "tokens in sequence");
            self.received = *seq;
            let confidential = *conf == 1;
            (
                data.iter()
                    .map(|b| if confidential { !b } else { *b })
                    .collect(),
                confidential,
            )
        }
    }

    pub(crate) fn frame(mtyp: u8, token: &[u8]) -> Vec<u8> {
        message(mtyp, token).unwrap()
    }

    #[test]
    fn messages_have_a_two_octet_length() {
        assert_eq!(frame(1, b"ab"), [1, 1, 0, 2, b'a', b'b']);
        assert_eq!(frame(3, &[]), [1, 3, 0, 0]);
        assert!(message(1, &vec![0; MAX_TOKEN + 1]).is_err());
        assert_eq!(frame(2, &vec![7; MAX_TOKEN]).len(), 4 + MAX_TOKEN);
    }

    /// Runs `authenticate` against what a client sends; returns its result
    /// and what the server wrote.
    async fn run(
        acceptor: &Toy,
        client: &[u8],
    ) -> (io::Result<(Box<dyn Context>, Protection, String)>, Vec<u8>) {
        let (mut ours, mut theirs) = tokio::io::duplex(1 << 20);
        theirs.write_all(client).await.unwrap();
        drop(theirs.shutdown().await);
        let result = authenticate(&mut ours, acceptor).await;
        drop(ours);
        if result.is_err() {
            assert_eq!(
                acceptor.live.load(Ordering::SeqCst),
                0,
                "a failed authentication keeps no context"
            );
        }
        let mut written = Vec::new();
        theirs.read_to_end(&mut written).await.unwrap();
        (result, written)
    }

    fn level(client: &mut ToyClient, n: u8) -> Vec<u8> {
        frame(PROTECTION, &client.wrap(false, &[n]))
    }

    #[tokio::test]
    async fn negotiation() {
        let both = INTEG_FLAG | CONF_FLAG;
        for (flags, asked, agreed) in [
            (both, 1, Protection::Integrity),
            (both, 2, Protection::Confidentiality),
            (both, 3, Protection::Confidentiality),
            (INTEG_FLAG, 2, Protection::Integrity),
            (INTEG_FLAG, 3, Protection::Integrity),
        ] {
            let toy = Toy::new(flags, 1);
            let mut client = ToyClient::new();
            let mut input = frame(AUTHENTICATION, b"hello");
            input.extend(level(&mut client, asked));
            let (result, written) = run(&toy, &input).await;
            let (_, protection, peer) = result.unwrap();
            assert_eq!((protection, peer.as_str()), (agreed, "alice@TEST"));
            let reply = frame(AUTHENTICATION, b"welcome");
            assert_eq!(&written[..reply.len()], reply);
            // The answer is wrapped without confidentiality (section 4.4).
            let [1, 2, 0, 3, rest @ ..] = &written[reply.len()..] else {
                panic!("{written:?}")
            };
            assert_eq!(client.unwrap(rest), (vec![agreed as u8], false));
        }

        // Two rounds of context establishment.
        let toy = Toy::new(both, 2);
        let mut client = ToyClient::new();
        let mut input = frame(AUTHENTICATION, b"hello");
        input.extend(frame(AUTHENTICATION, b"hello"));
        input.extend(level(&mut client, 2));
        let (result, written) = run(&toy, &input).await;
        assert!(result.is_ok());
        assert!(
            written.starts_with(
                &[
                    frame(AUTHENTICATION, b"again"),
                    frame(AUTHENTICATION, b"welcome")
                ]
                .concat()
            )
        );
    }

    #[tokio::test]
    async fn rejection_and_malformed_messages() {
        let toy = Toy::new(INTEG_FLAG | CONF_FLAG, 1);
        let abort = [VERSION, ABORT];
        // A token the mechanism rejects, a wrong message type, a principal
        // that may not use the proxy, and too many rounds: abort messages.
        for input in [
            frame(AUTHENTICATION, b"nonsense"),
            frame(PROTECTION, b"hello"),
            frame(ENCAPSULATED, b"x"),
        ] {
            let (result, written) = run(&toy, &input).await;
            assert!(result.is_err());
            assert_eq!(written, abort, "{input:?}");
        }
        let mallory = Toy {
            peer: "mallory@TEST",
            ..toy.clone()
        };
        let (result, written) = run(&mallory, &frame(AUTHENTICATION, b"hello")).await;
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("may not use the proxy")
        );
        assert!(written.ends_with(&abort));
        let forever = Toy::new(toy.flags, 100);
        let input: Vec<u8> = (0..=MAX_ROUNDS)
            .flat_map(|_| frame(AUTHENTICATION, b"hello"))
            .collect();
        let (result, written) = run(&forever, &input).await;
        assert!(result.is_err());
        assert!(written.ends_with(&abort));
        // No integrity, no use.
        let weak = Toy::new(0, 1);
        let (result, written) = run(&weak, &frame(AUTHENTICATION, b"hello")).await;
        assert!(result.is_err());
        assert!(written.ends_with(&abort));

        // Malformed: another version, a cut message, the client's abort, an
        // unknown or unwrapped protection level.
        let (result, written) = run(&toy, &[2, 1, 0, 0]).await;
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidData);
        assert!(written.is_empty());
        let (result, _) = run(&toy, &[1, 1, 0, 9, b'h']).await;
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::UnexpectedEof);
        let (result, written) = run(&toy, &abort).await;
        assert_eq!(
            result.err().unwrap().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(written.is_empty());
        for bad in [0u8, 4, 0xff] {
            let mut client = ToyClient::new();
            let mut input = frame(AUTHENTICATION, b"hello");
            input.extend(level(&mut client, bad));
            assert!(run(&toy, &input).await.0.is_err(), "level {bad}");
        }
        let mut input = frame(AUTHENTICATION, b"hello");
        input.extend(frame(PROTECTION, &[]));
        assert!(
            run(&toy, &input).await.0.is_err(),
            "an empty token is no level"
        );
        let mut input = frame(AUTHENTICATION, b"hello");
        input.extend(frame(ENCAPSULATED, &ToyClient::new().wrap(false, &[1])));
        assert!(run(&toy, &input).await.0.is_err(), "data before the level");
    }

    #[tokio::test]
    async fn encapsulated_streams_and_datagrams() {
        for (protection, confidential) in [
            (Protection::Integrity, false),
            (Protection::Confidentiality, true),
        ] {
            let toy = Toy::new(INTEG_FLAG | CONF_FLAG, 1);
            let context = toy.context().unwrap();
            let (ours, mut theirs) = tokio::io::duplex(1 << 20);
            let mut stream = Stream::new(ours, context, protection).unwrap();
            let mut client = ToyClient::new();

            // Messages split anywhere, empty ones included, read as a stream.
            let mut input = frame(ENCAPSULATED, &client.wrap(confidential, b"hello "));
            input.extend(frame(ENCAPSULATED, &client.wrap(confidential, b"")));
            input.extend(frame(ENCAPSULATED, &client.wrap(confidential, b"world")));
            for byte in &input {
                theirs.write_all(&[*byte]).await.unwrap();
            }
            let mut got = [0u8; 11];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hello world");

            // Writes are wrapped in messages of at most MAX_CHUNK bytes.
            let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
            stream.write_all(&data).await.unwrap();
            stream.flush().await.unwrap();
            let mut received = Vec::new();
            while received.len() < data.len() {
                let (mtyp, token) = read_message(&mut theirs).await.unwrap();
                assert_eq!(mtyp, ENCAPSULATED);
                let (chunk, conf) = client.unwrap(&token);
                assert!(chunk.len() <= MAX_CHUNK);
                assert_eq!(conf, confidential);
                received.extend(chunk);
            }
            assert_eq!(received, data);

            // Datagrams: one message each.
            let (shared, agreed) = stream.security();
            let datagram = frame(ENCAPSULATED, &client.wrap(confidential, b"udp request"));
            assert_eq!(
                open_datagram(&shared, agreed, &datagram).unwrap(),
                b"udp request"
            );
            assert_eq!(
                open_datagram(&shared, agreed, &datagram),
                None,
                "a replayed datagram"
            );
            assert_eq!(
                open_datagram(&shared, agreed, &datagram[..datagram.len() - 1]),
                None,
                "cut short"
            );
            assert_eq!(
                open_datagram(&shared, agreed, &[1, 2, 0, 0]),
                None,
                "another type"
            );
            let sealed = seal_datagram(&shared, agreed, b"udp reply").unwrap();
            let (mtyp, token) = read_message(&mut &sealed[..]).await.unwrap();
            assert_eq!(mtyp, ENCAPSULATED);
            assert_eq!(client.unwrap(&token), (b"udp reply".to_vec(), confidential));

            // EOF between messages ends the stream; inside one, it is an error.
            theirs
                .write_all(&frame(ENCAPSULATED, &client.wrap(confidential, b"last"))[..5])
                .await
                .unwrap();
            drop(theirs);
            let mut rest = Vec::new();
            assert_eq!(
                stream.read_to_end(&mut rest).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }

        // Protection is enforced: unencrypted data where encryption was
        // agreed, tokens out of sequence, and other message types end it.
        let toy = Toy::new(INTEG_FLAG | CONF_FLAG, 1);
        for input in [
            frame(ENCAPSULATED, &ToyClient::new().wrap(false, b"plain")),
            frame(ENCAPSULATED, &[1, 5, b'x']),
            frame(AUTHENTICATION, &ToyClient::new().wrap(true, b"x")),
            vec![VERSION, ABORT],
            vec![VERSION, ENCAPSULATED, 0, 0],
        ] {
            let (ours, mut theirs) = tokio::io::duplex(1 << 16);
            let mut stream =
                Stream::new(ours, toy.context().unwrap(), Protection::Confidentiality).unwrap();
            theirs.write_all(&input).await.unwrap();
            drop(theirs);
            let mut rest = Vec::new();
            assert_eq!(
                stream.read_to_end(&mut rest).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{input:?}"
            );
        }
        // An empty connection is an empty stream.
        let (ours, theirs) = tokio::io::duplex(16);
        drop(theirs);
        let mut stream = Stream::new(ours, toy.context().unwrap(), Protection::Integrity).unwrap();
        let mut rest = Vec::new();
        assert_eq!(stream.read_to_end(&mut rest).await.unwrap(), 0);
    }

    #[test]
    fn the_system_library() {
        match library() {
            Ok(lib) => assert!(!lib.hostbased_service.is_null()),
            // GSS.framework is part of macOS. Elsewhere the library is needed
            // only once GSS-API is configured (tests/socks-gssapi.sh uses it).
            Err(e) => assert!(
                !cfg!(target_os = "macos") && e.starts_with("loading the GSS-API library"),
                "{e}"
            ),
        }
        let e = Kerberos::new(Path::new("/nonexistent/keytab"), Vec::new())
            .err()
            .unwrap();
        assert!(
            e.contains("/nonexistent/keytab") || e.starts_with("loading the GSS-API library"),
            "{e}"
        );
    }
}
