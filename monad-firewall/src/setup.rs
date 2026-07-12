// Bump the memlock rlimit. This is needed for older kernels that don't use the
// new memcg based accounting, see https://lwn.net/Articles/837122/
// Meanwhile monad is mostly on the new kernels, we still have this guard just in case
pub fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}
