fn check_remote_debugger_present() -> bool {
    unsafe {
        let mut is_debugger_present: i32 = 0;
        kernel32::CheckRemoteDebuggerPresent(
            kernel32::GetCurrentProcess(),
            std::ptr::addr_of_mut!(is_debugger_present),
        );
        is_debugger_present != 0
    }
}
