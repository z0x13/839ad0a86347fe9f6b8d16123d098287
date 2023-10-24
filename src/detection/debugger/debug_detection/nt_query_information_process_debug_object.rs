fn nt_query_information_process_debug_object() -> bool {
    unsafe {
        let mut dbg_object: u64 = 0;
        let _res = windows_sys::Win32::System::Threading::NtQueryInformationProcess(
            kernel32::GetCurrentProcess() as isize,
            0x1e,
            std::ptr::addr_of_mut!(dbg_object).cast(),
            u32::try_from(std::mem::size_of_val(&dbg_object)).unwrap(),
            std::ptr::null_mut(),
        );
        dbg_object != 0
    }
}
