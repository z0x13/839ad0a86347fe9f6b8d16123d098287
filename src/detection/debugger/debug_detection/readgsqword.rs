#[inline]
#[cfg(target_pointer_width = "64")]
pub unsafe fn __readgsqword(offset: std::os::raw::c_ulong) -> winapi::ctypes::__uint64 {
    let out: u64;
    std::arch::asm!(
    "mov {}, gs:[{:e}]",
    lateout(reg) out,
    in(reg) offset,
    options(nostack, pure, readonly),
    );
    out
}
