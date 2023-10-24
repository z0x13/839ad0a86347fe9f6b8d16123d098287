pub fn cursor_position() -> bool {
    let mut cursor: winapi::shared::windef::POINT =
        winapi::shared::windef::POINT { x: 0i32, y: 0i32 };
    unsafe {
        winapi::um::winuser::GetCursorPos(&mut cursor);
        let x = cursor.x;
        let y = cursor.y;
        winapi::um::synchapi::Sleep(5000);
        winapi::um::winuser::GetCursorPos(&mut cursor);
        if x == cursor.x && y == cursor.y {
            return true;
        }
    }
    false
}
