pub fn rdtsc() -> bool {
    let (mut eax, mut edx): (u64, u64);
    let (start, finish): (u128, u128);
    unsafe {
        std::arch::asm!(
        "rdtsc",
        out("eax") eax,
        out("edx") edx
        );
    }
    start = ((edx << 32) | eax) as u128;
    unsafe {
        std::arch::asm!(
        "rdtsc",
        out("eax") eax,
        out("edx") edx
        );
    }
    finish = ((edx << 32) | eax) as u128;
    finish - start > 1000
}
