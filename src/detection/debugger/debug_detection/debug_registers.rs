fn debug_registers() -> bool {
    unsafe {
        let mut debug_context: windows_sys::Win32::System::Diagnostics::Debug::CONTEXT =
            std::mem::MaybeUninit::zeroed().assume_init();
        kernel32::GetThreadContext(
            kernel32::GetCurrentThread(),
            std::ptr::addr_of_mut!(debug_context).cast(),
        );
        debug_context.Dr0 != 0
            || debug_context.Dr1 != 0
            || debug_context.Dr2 != 0
            || debug_context.Dr3 != 0
    }
}
