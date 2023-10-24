pub fn cpuid_vendor() -> bool {
    let (mut ebx, mut ecx, mut edx): (u32, u32, u32);
    unsafe {
        std::arch::asm!(
        "mov eax, 0x40000000",
        "cpuid",
        "mov eax, ebx",
        out("eax") ebx,
        out("ecx") ecx,
        out("edx") edx
        );
    }
    let vendor = vec![
        ebx as u8,
        (ebx >> 8) as u8,
        (ebx >> 16) as u8,
        (ebx >> 24) as u8,
        ecx as u8,
        (ecx >> 8) as u8,
        (ecx >> 16) as u8,
        (ecx >> 24) as u8,
        edx as u8,
        (edx >> 8) as u8,
        (edx >> 16) as u8,
        (edx >> 24) as u8,
    ];
    vendor != [77, 105, 99, 114, 111, 115, 111, 102, 116, 32, 72, 118] && vendor != [0u8; 12]
}
