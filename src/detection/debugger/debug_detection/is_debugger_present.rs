fn is_debugger_present() -> bool {
    unsafe {
        if winapi::um::debugapi::IsDebuggerPresent() != 0 {
            return true;
        }
        false
    }
}
