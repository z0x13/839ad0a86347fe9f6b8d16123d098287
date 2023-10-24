fn hide_from_debugger() {
    unsafe {
        windows_sys::Win32::System::Threading::NtSetInformationThread(
            windows_sys::Win32::System::Threading::GetCurrentThread(),
            // THREAD_INFORMATION_CLASS::ThreadHideFromDebugger
            0x11,
            std::ptr::null_mut(),
            0,
        );
    }
}
