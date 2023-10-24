use crate::detection::debugger::debug_detection::readgsqword::__readgsqword;

fn peb_heap_flags() -> bool {
    const HEAP_GROWABLE: u32 = 2;
    unsafe {
        let peb_offset: *const u64 = __readgsqword(0x60) as *const u64;
        let heap_ptr = (peb_offset as u64 + 0x30) as *const u64;
        let heap_flags_ptr = (*heap_ptr + 0x70) as *const u32;
        let heap_force_flags_ptr = (*heap_ptr + 0x74) as *const u32;
        (*heap_flags_ptr & !HEAP_GROWABLE) != 0 || *heap_force_flags_ptr != 0
    }
}
