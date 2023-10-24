fn nt_query_information_process_debug_port() -> bool {
    unsafe {
        let mut dbg_port: u64 = 0;
        let res = windows_sys::Win32::System::Threading::NtQueryInformationProcess(
            kernel32::GetCurrentProcess() as isize,
            7,
            std::ptr::addr_of_mut!(dbg_port).cast(),
            u32::try_from(std::mem::size_of_val(&dbg_port)).unwrap(),
            std::ptr::null_mut(),
        );
        res == 0 && dbg_port != 0
    }
}
