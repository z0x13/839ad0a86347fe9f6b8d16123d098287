pub fn cpuid_hv_bit() -> bool {
    let mut ecx: u32;
    unsafe {
        std::arch::asm!(
        "mov eax, 1",
        "cpuid",
        out("ecx") ecx
        );
    }
    (ecx >> 31) & 1 == 1
}
