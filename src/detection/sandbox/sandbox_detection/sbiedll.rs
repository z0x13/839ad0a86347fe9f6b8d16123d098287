pub fn sbiedll() -> bool {
    let module_name = std::ffi::CString::new("sbiedll.dll").unwrap();
    unsafe {
        let module_lpstr: winapi::um::winnt::LPSTR =
            std::mem::transmute::<*const i8, winapi::um::winnt::LPSTR>(module_name.as_ptr());
        !kernel32::GetModuleHandleA(module_lpstr).is_null()
    }
}
