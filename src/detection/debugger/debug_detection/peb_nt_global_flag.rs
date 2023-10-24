use crate::detection::debugger::debug_detection::readgsqword::__readgsqword;

fn peb_nt_global_flag() -> bool {
    unsafe {
        let peb_offset: *const u64 = __readgsqword(0x60) as *const u64;
        let nt_global_flag = *(((peb_offset as *const u8) as u64 + 0xbc) as *const u32);
        nt_global_flag == 0x70
    }
}
