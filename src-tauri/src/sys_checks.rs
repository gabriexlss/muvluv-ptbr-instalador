use std::path::Path;

/// Checks if `muvluv16.exe` is currently running on the system.
#[cfg(windows)]
pub fn is_game_running() -> bool {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
            return false;
        }
        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        let mut running = false;
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe_name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                if exe_name.eq_ignore_ascii_case("muvluv16.exe") {
                    running = true;
                    break;
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        running
    }
}

#[cfg(not(windows))]
pub fn is_game_running() -> bool {
    false
}

/// Returns available free bytes on the volume containing `path`.
#[cfg(windows)]
pub fn available_disk_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let target = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    let mut wide: Vec<u16> = target.as_os_str().encode_wide().collect();
    wide.push(0);

    let mut free_avail: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut total_free: u64 = 0;

    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_avail,
            &mut total_bytes,
            &mut total_free,
        )
    };
    if ok != 0 {
        Some(free_avail)
    } else {
        None
    }
}

#[cfg(unix)]
pub fn available_disk_space(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;

    let target = if path.exists() {
        path
    } else {
        path.parent().unwrap_or(Path::new("/"))
    };
    let c_path = CString::new(target.as_os_str().as_bytes()).ok()?;
    let mut stat = MaybeUninit::<libc::statvfs>::uninit();
    let res = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if res == 0 {
        let s = unsafe { stat.assume_init() };
        Some((s.f_bavail as u64).saturating_mul(s.f_frsize as u64))
    } else {
        None
    }
}
