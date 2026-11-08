/// Memory hygiene and anti-paging primitives
/// Implements process-wide mlockall and buffer memory locking to prevent
/// private keys, plaintext, and ephemeral secrets from being swapped to disk or dumped.

/// Locks all current and future process memory pages into RAM using mlockall.
/// If RLIMIT_MEMLOCK restricts locking or the platform is non-Unix, returns false gracefully.
pub fn lock_process_memory() -> bool {
    #[cfg(unix)]
    unsafe {
        let res = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
        res == 0
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Locks a specific slice of memory to prevent paging to swap.
pub fn lock_slice(data: &[u8]) -> bool {
    #[cfg(unix)]
    unsafe {
        if data.is_empty() {
            return true;
        }
        let res = libc::mlock(data.as_ptr() as *const libc::c_void, data.len());
        res == 0
    }
    #[cfg(not(unix))]
    {
        let _ = data;
        false
    }
}

/// Unlocks a previously locked memory slice.
pub fn unlock_slice(data: &[u8]) {
    #[cfg(unix)]
    unsafe {
        if !data.is_empty() {
            libc::munlock(data.as_ptr() as *const libc::c_void, data.len());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = data;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_locking_slice() {
        let sensitive = vec![0x42u8; 1024];
        let _ = lock_slice(&sensitive);
        unlock_slice(&sensitive);
    }

    #[test]
    fn test_process_memory_lock() {
        // Calling lock_process_memory shouldn't panic, returns bool depending on rlimit
        let _ = lock_process_memory();
    }
}
