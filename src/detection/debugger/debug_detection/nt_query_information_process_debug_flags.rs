fn nt_query_information_process_debug_flags() -> bool {
    unsafe {
        let mut dbg_flags: u32 = 0;
        let res = windows_sys::Win32::System::Threading::NtQueryInformationProcess(
            kernel32::GetCurrentProcess() as isize,
            0x1f,
            std::ptr::addr_of_mut!(dbg_flags).cast(),
            u32::try_from(std::mem::size_of_val(&dbg_flags)).unwrap(),
            std::ptr::null_mut(),
        );
        res == 0 && dbg_flags == 0
    }
}
