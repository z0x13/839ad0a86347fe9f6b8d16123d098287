pub fn input_time() -> bool {
    unsafe {
        let mut last_input_info: winapi::um::winuser::LASTINPUTINFO =
            winapi::um::winuser::LASTINPUTINFO {
                cbSize: std::mem::size_of::<winapi::um::winuser::LASTINPUTINFO>() as u32,
                dwTime: 0u32,
            };
        winapi::um::winuser::GetLastInputInfo(&mut last_input_info);
        let idle_time: u32 = (kernel32::GetTickCount() - last_input_info.dwTime) / 1000;
        if idle_time >= 60 {
            return true;
        }
        false
    }
}
