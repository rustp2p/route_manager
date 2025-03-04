use crate::RouteListener;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub(crate) struct EventFd(std::fs::File);
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
impl EventFd {
    pub(crate) fn new() -> io::Result<Self> {
        #[cfg(not(target_os = "espidf"))]
        let flags = libc::EFD_CLOEXEC | libc::EFD_NONBLOCK;
        // ESP-IDF is EFD_NONBLOCK by default and errors if you try to pass this flag.
        #[cfg(target_os = "espidf")]
        let flags = 0;
        let event_fd = unsafe { libc::eventfd(0, flags) };
        if event_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        use std::os::fd::FromRawFd;
        let file = unsafe { std::fs::File::from_raw_fd(event_fd) };
        Ok(Self(file))
    }
    fn wake(&self) -> io::Result<()> {
        use std::io::Write;
        let buf: [u8; 8] = 1u64.to_ne_bytes();
        match (&self.0).write_all(&buf) {
            Ok(_) => Ok(()),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(err) => Err(err),
        }
    }
    fn as_event_fd(&self) -> libc::c_int {
        self.0.as_raw_fd() as _
    }
}
#[cfg(target_os = "macos")]
struct EventFd(libc::c_int, libc::c_int);
#[cfg(target_os = "macos")]
impl EventFd {
    fn new() -> io::Result<Self> {
        let mut fds: [libc::c_int; 2] = [0; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        let read_fd = fds[0];
        let write_fd = fds[1];
        Ok(Self(read_fd, write_fd))
    }
    fn wake(&self) -> io::Result<()> {
        let buf: [u8; 8] = 1u64.to_ne_bytes();
        let res = unsafe { libc::write(self.1, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if res == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn as_event_fd(&self) -> libc::c_int {
        self.0
    }
}
#[cfg(target_os = "macos")]
impl Drop for EventFd {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.0);
            let _ = libc::close(self.1);
        }
    }
}
impl RouteListener {
    pub(crate) fn wait(&self) -> io::Result<()> {
        let fd = self.as_raw_fd() as libc::c_int;

        let event_fd = self.shutdown_handle.event_fd.as_event_fd();
        let mut readfds: libc::fd_set = unsafe { std::mem::zeroed() };
        unsafe {
            libc::FD_SET(fd, &mut readfds);
            libc::FD_SET(event_fd, &mut readfds);
        }
        let result = unsafe {
            libc::select(
                fd.max(event_fd) + 1,
                &mut readfds,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if self.shutdown_handle.is_shutdown.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "shutdown"));
        }
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        if result == 0 {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        Ok(())
    }
    /// Retrieves a shutdown handle for the RouteListener.
    pub fn shutdown_handle(&self) -> io::Result<RouteListenerShutdown> {
        Ok(self.shutdown_handle.clone())
    }
}

/// Shutdown handle for the RouteListener, used to stop listening.
#[derive(Clone)]
pub struct RouteListenerShutdown {
    is_shutdown: Arc<AtomicBool>,
    event_fd: Arc<EventFd>,
}
impl RouteListenerShutdown {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            is_shutdown: Arc::new(Default::default()),
            event_fd: Arc::new(EventFd::new()?),
        })
    }
    /// Shuts down the RouteListener.
    pub fn shutdown(&self) -> io::Result<()> {
        self.is_shutdown.store(true, Ordering::Relaxed);
        self.event_fd.wake()
    }
}
