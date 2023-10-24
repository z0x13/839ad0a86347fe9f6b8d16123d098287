use crate::detection::debugger::debug_detection::readgsqword::__readgsqword;

fn peb_is_debugger_present() -> bool {
    unsafe {
        let peb_offset: *const u64 = __readgsqword(0x60) as *const u64;
        let is_debugger_present = *(((peb_offset as *const u8) as u64 + 0x02) as *const u8);
        is_debugger_present == 1
    }
}
