// See https://github.com/johnyburd/net-route/blob/main/src/platform_impl/macos/macos.rs
// https://github.com/freebsd/freebsd-src/blob/main/sbin/route/route.c
// https://github.com/openbsd/src/blob/master/sbin/route/route.c

use crate::{Route, RouteChange};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::{io, mem};
#[cfg(any(feature = "async", feature = "async_io"))]
mod async_route;
#[cfg(any(feature = "async", feature = "async_io"))]
pub use async_route::*;
mod bind;
use crate::if_index_to_name;
use bind::*;
/// RouteListener for receiving route change events.
pub struct RouteListener {
    list: VecDeque<RouteChange>,
    route_socket: UnixStream,
    #[cfg(feature = "shutdown")]
    pub(crate) shutdown_handle: crate::RouteListenerShutdown,
}
impl RouteListener {
    /// Creates a new RouteListener.
    pub fn new() -> io::Result<Self> {
        let route_socket = create_route_socket()?;
        #[cfg(feature = "shutdown")]
        route_socket.set_nonblocking(true)?;
        Ok(RouteListener {
            list: Default::default(),
            route_socket,
            #[cfg(feature = "shutdown")]
            shutdown_handle: crate::RouteListenerShutdown::new()?,
        })
    }

    /// Listens for a route change event and returns a RouteChange.
    #[cfg(not(feature = "shutdown"))]
    pub fn listen(&mut self) -> io::Result<RouteChange> {
        if let Some(route) = self.list.pop_front() {
            return Ok(route);
        }
        let mut buf = [0u8; 4096];
        let route_socket = &mut self.route_socket;
        loop {
            let len = route_socket.read(&mut buf)?;

            deserialize_res_change(
                |route| {
                    self.list.push_back(route);
                },
                &buf[..len],
            )?;
            if let Some(route) = self.list.pop_front() {
                return Ok(route);
            }
        }
    }
}
impl AsRawFd for RouteListener {
    fn as_raw_fd(&self) -> RawFd {
        self.route_socket.as_raw_fd()
    }
}
impl RouteListener {
    /// Listens for a route change event and returns a RouteChange.
    #[cfg(feature = "shutdown")]
    pub fn listen(&mut self) -> io::Result<RouteChange> {
        if let Some(route) = self.list.pop_front() {
            return Ok(route);
        }
        let mut buf = [0u8; 4096];
        loop {
            self.wait()?;
            let len = match self.route_socket.read(&mut buf) {
                Ok(list) => list,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            };
            deserialize_res_change(
                |route| {
                    self.list.push_back(route);
                },
                &buf[..len],
            )?;
            if let Some(route) = self.list.pop_front() {
                return Ok(route);
            }
        }
    }
}

/// RouteManager is used for managing routes (adding, deleting, and listing).
pub struct RouteManager {
    _private: std::marker::PhantomData<()>,
}
impl RouteManager {
    /// Creates a new RouteManager.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            _private: std::marker::PhantomData,
        })
    }
    /// Returns a new instance of RouteListener.
    pub fn listener() -> io::Result<RouteListener> {
        RouteListener::new()
    }
    /// Lists all current routes.
    pub fn list(&mut self) -> io::Result<Vec<Route>> {
        list_routes()
    }
    /// Adds a new route.
    pub fn add(&mut self, route: &Route) -> io::Result<()> {
        add_route(route)
    }
    /// Deletes an existing route.
    pub fn delete(&mut self, route: &Route) -> io::Result<()> {
        delete_route(route)
    }
}

fn try_get_msg_buf() -> io::Result<Vec<u8>> {
    const MAX_RETRYS: usize = 3;

    for _ in 0..MAX_RETRYS {
        let mut mib: [u32; 6] = [0; 6];
        let mut len = 0;

        mib[0] = CTL_NET;
        mib[1] = AF_ROUTE;
        mib[2] = 0;
        mib[3] = 0; // family: ipv4 & ipv6
        mib[4] = NET_RT_DUMP;
        // mib[5] flags: 0

        // see: https://github.com/golang/net/blob/ec05fdcd71141c885f3fb84c41d1c692f094ccbe/route/route.go#L126
        if unsafe {
            sysctl(
                &mut mib as *mut _ as *mut _,
                6,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut msgs_buf: Vec<u8> = vec![0; len];

        if unsafe {
            sysctl(
                &mut mib as *mut _ as *mut _,
                6,
                msgs_buf.as_mut_ptr() as _,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } < 0
        {
            // will retry return error if
            continue;
        } else {
            return Ok(msgs_buf);
        }
    }

    Err(io::Error::other("Failed to get routing table"))
}

fn list_routes() -> io::Result<Vec<Route>> {
    let msgs_buf = try_get_msg_buf()?;

    let mut routes = vec![];
    deserialize_res(
        |rtm_type, route| {
            if rtm_type == RTM_GET {
                routes.push(route);
            }
        },
        &msgs_buf,
    )?;
    Ok(routes)
}

fn add_route(route: &Route) -> io::Result<()> {
    add_or_del_route(route, RTM_ADD as u8)
}
fn delete_route(route: &Route) -> io::Result<()> {
    add_or_del_route(route, RTM_DELETE as u8)
}

fn add_or_del_route_req(route: &Route, rtm_type: u8) -> io::Result<m_rtmsg> {
    let mut rtm_flags = RTF_STATIC | RTF_UP;

    if route.gateway.is_some() {
        rtm_flags |= RTF_GATEWAY;
    }

    if (route.destination.is_ipv4() && route.prefix == 32)
        || (route.destination.is_ipv6() && route.prefix == 128)
    {
        rtm_flags |= RTF_HOST;
    }

    let mut rtm_addrs = RTA_DST | RTA_NETMASK;
    if rtm_type == RTM_ADD as u8 || route.gateway.is_some() {
        rtm_addrs |= RTA_GATEWAY;
    }
    let mut rtmsg: m_rtmsg = route_to_m_rtmsg(rtm_type, route)?;

    rtmsg.hdr.rtm_addrs = rtm_addrs as i32;
    rtmsg.hdr.rtm_seq = 1;
    rtmsg.hdr.rtm_flags = rtm_flags as i32;
    rtmsg.hdr.rtm_type = rtm_type;
    rtmsg.hdr.rtm_version = RTM_VERSION as u8;
    Ok(rtmsg)
}

fn add_or_del_route(route: &Route, rtm_type: u8) -> io::Result<()> {
    let rtmsg = add_or_del_route_req(route, rtm_type)?;
    let fd = unsafe { socket(PF_ROUTE as i32, SOCK_RAW as i32, AF_UNSPEC as i32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut route_fd = unsafe { UnixStream::from_raw_fd(fd) };

    route_fd.write_all(rtmsg.slice())?;

    let mut buf = [0u8; std::mem::size_of::<m_rtmsg>()];

    let len = route_fd.read(&mut buf)?;
    deserialize_res(|_, _| {}, &buf[..len])?;

    Ok(())
}
fn route_to_m_rtmsg(_rtm_type: u8, value: &Route) -> io::Result<m_rtmsg> {
    value.check()?;
    let mut rtmsg = m_rtmsg {
        hdr: rt_msghdr::default(),
        attrs: [0u8; 512],
    };

    let mut attr_offset = put_ip_addr(0, &mut rtmsg, value.destination)?;

    if let Some(gateway) = value.gateway {
        attr_offset = put_ip_addr(attr_offset, &mut rtmsg, gateway)?;
    }

    if _rtm_type == RTM_ADD as u8 && value.gateway.is_none() {
        if let Some(if_index) = value.get_index() {
            attr_offset = put_ifa_addr(attr_offset, &mut rtmsg, if_index)?;
        }
    }

    attr_offset = put_ip_addr(attr_offset, &mut rtmsg, value.mask())?;
    if _rtm_type != RTM_ADD as u8 || value.gateway.is_none() {
        if let Some(if_index) = value.get_index() {
            attr_offset = put_ifa_addr(attr_offset, &mut rtmsg, if_index)?;
        }
    }

    let msg_len = std::mem::size_of::<rt_msghdr>() + attr_offset;
    #[cfg(target_os = "openbsd")]
    {
        rtmsg.hdr.rtm_hdrlen = std::mem::size_of::<rt_msghdr>() as u16;
    }
    rtmsg.hdr.rtm_msglen = msg_len as u16;
    Ok(rtmsg)
}

fn put_ifa_addr(mut attr_offset: usize, rtmsg: &mut m_rtmsg, if_index: u32) -> io::Result<usize> {
    let sdl_len = std::mem::size_of::<sockaddr_dl>();
    let sa_dl = sockaddr_dl {
        sdl_len: sdl_len as u8,
        sdl_family: AF_LINK as u8,
        sdl_index: if_index as u16,
        ..Default::default()
    };

    let sa_ptr = &sa_dl as *const sockaddr_dl as *const u8;
    let sa_bytes = unsafe { std::slice::from_raw_parts(sa_ptr, sdl_len) };
    rtmsg.attrs[attr_offset..attr_offset + sdl_len].copy_from_slice(sa_bytes);

    attr_offset += sa_size(sdl_len);
    Ok(attr_offset)
}
fn put_ip_addr(mut attr_offset: usize, rtmsg: &mut m_rtmsg, addr: IpAddr) -> io::Result<usize> {
    match addr {
        IpAddr::V4(addr) => {
            let sa_len = std::mem::size_of::<sockaddr_in>();
            let sa_in: sockaddr_in = addr.into();

            let sa_ptr = &sa_in as *const sockaddr_in as *const u8;
            let sa_bytes = unsafe { std::slice::from_raw_parts(sa_ptr, sa_len) };
            rtmsg.attrs[attr_offset..attr_offset + sa_len].copy_from_slice(sa_bytes);

            attr_offset += sa_size(sa_len);
        }
        IpAddr::V6(addr) => {
            let sa_len = std::mem::size_of::<sockaddr_in6>();
            let sa_in: sockaddr_in6 = addr.into();

            let sa_ptr = &sa_in as *const sockaddr_in6 as *const u8;
            let sa_bytes = unsafe { std::slice::from_raw_parts(sa_ptr, sa_len) };
            rtmsg.attrs[attr_offset..attr_offset + sa_len].copy_from_slice(sa_bytes);

            attr_offset += sa_size(sa_len);
        }
    }
    Ok(attr_offset)
}
#[cfg(target_os = "macos")]
fn sa_size(len: usize) -> usize {
    len
}
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
fn sa_size(sa_len: usize) -> usize {
    // See https://github.com/freebsd/freebsd-src/blob/7e51bc6cdd5c317109e25b0b64230d00d68dceb3/contrib/bsnmp/lib/support.h#L89
    if sa_len == 0 {
        return std::mem::size_of::<libc::c_long>();
    }
    1 + ((sa_len - 1) | (std::mem::size_of::<libc::c_long>() - 1))
}
fn deserialize_res_change<F: FnMut(RouteChange)>(mut add_fn: F, msgs_buf: &[u8]) -> io::Result<()> {
    deserialize_res(
        |rtm_type, route| {
            let route = match rtm_type {
                RTM_ADD => RouteChange::Add(route),
                RTM_DELETE => RouteChange::Delete(route),
                RTM_CHANGE => RouteChange::Change(route),
                _ => return,
            };
            add_fn(route);
        },
        msgs_buf,
    )
}
fn deserialize_res<F: FnMut(u32, Route)>(mut add_fn: F, msgs_buf: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset + std::mem::size_of::<rt_msghdr>() <= msgs_buf.len() {
        let buf = &msgs_buf[offset..];

        let rt_hdr = unsafe { &*buf.as_ptr().cast::<rt_msghdr>() };
        let msg_len = rt_hdr.rtm_msglen as usize;
        if msg_len == 0 {
            break;
        }
        offset += msg_len;
        if rt_hdr.rtm_version as u32 != RTM_VERSION {
            continue;
        }
        #[cfg(target_os = "openbsd")]
        if (rt_hdr.rtm_flags as u32 & (RTF_GATEWAY | RTF_STATIC | RTF_LLINFO)) == 0 {
            continue;
        }
        #[cfg(target_os = "openbsd")]
        if (rt_hdr.rtm_flags as u32 & (RTF_LOCAL | RTF_BROADCAST)) != 0 {
            continue;
        }
        if rt_hdr.rtm_errno != 0 {
            return Err(io::Error::from_raw_os_error(rt_hdr.rtm_errno));
        }

        #[cfg(target_os = "macos")]
        if rt_hdr.rtm_flags as u32 & RTF_WASCLONED != 0 {
            continue;
        }

        let rt_msg = &buf[std::mem::size_of::<rt_msghdr>()..msg_len];

        if let Some(route) = message_to_route(rt_hdr, rt_msg) {
            add_fn(rt_hdr.rtm_type as u32, route);
        }
    }
    Ok(())
}

fn message_to_route(hdr: &rt_msghdr, msg: &[u8]) -> Option<Route> {
    let mut gateway = None;

    // check if message has no destination
    if hdr.rtm_addrs & (1 << RTAX_DST) == 0 {
        return None;
    }

    // The body of the route message (msg) is a list of `struct sockaddr`. However, thanks to v6,
    // the size

    // See https://opensource.apple.com/source/network_cmds/network_cmds-606.40.2/netstat.tproj/route.c.auto.html,
    // function `get_rtaddrs()`
    let mut route_addresses = [None; RTAX_MAX as usize];
    let mut cur_pos = 0;
    for (idx, item) in route_addresses
        .iter_mut()
        .enumerate()
        .take(RTAX_MAX as usize)
    {
        if hdr.rtm_addrs & (1 << idx) != 0 {
            let buf = &msg[cur_pos..];
            if buf.len() < std::mem::size_of::<sockaddr>() {
                continue;
            }
            assert!(buf.len() >= std::mem::size_of::<sockaddr>());
            let sa: &sockaddr = unsafe { &*(buf.as_ptr() as *const sockaddr) };
            assert!(buf.len() >= sa.sa_len as usize);
            *item = Some(sa);
            #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
            {
                cur_pos += sa_size(sa.sa_len as usize);
            }
            #[cfg(target_os = "macos")]
            {
                // see ROUNDUP() macro in the route.c file linked above.
                // The len needs to be a multiple of 4bytes
                let aligned_len = if sa.sa_len == 0 {
                    4
                } else {
                    ((sa.sa_len - 1) | 0x3) + 1
                };
                cur_pos += aligned_len as usize;
            }
        }
    }

    let destination = sa_to_ip(route_addresses[RTAX_DST as usize]?)?;
    let mut prefix = match destination {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    // check if message has a gateway
    if hdr.rtm_addrs & (1 << RTAX_GATEWAY) != 0 {
        let gw_sa = route_addresses[RTAX_GATEWAY as usize]?;
        gateway = sa_to_ip(gw_sa);
        if let Some(IpAddr::V6(v6gw)) = gateway {
            // unicast link local start with FE80::
            let is_unicast_ll = v6gw.segments()[0] == 0xfe80;
            // v6 multicast starts with FF
            let is_multicast = v6gw.octets()[0] == 0xff;
            // lower 4 bit of byte1 encode the multicast scope
            let multicast_scope = v6gw.octets()[1] & 0x0f;
            // scope 1 is interface/node-local. scope 2 is link-local
            // RFC4291, Sec. 2.7 for the gory details
            if is_unicast_ll || (is_multicast && (multicast_scope == 1 || multicast_scope == 2)) {
                // how fun. So it looks like some kernels encode the scope_id of the v6 address in
                // byte 2 & 3 of the gateway IP, if it's unicast link_local, or multicast with interface-local
                // or link-local scope. So we need to set these two bytes to 0 to turn it into the
                // real gateway address
                // Logic again taken from route.c (see link above), function `p_sockaddr()`
                let segs = v6gw.segments();
                gateway = Some(IpAddr::V6(Ipv6Addr::new(
                    segs[0], 0, segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
                )))
            }
        }
    }

    // check if message has netmask
    if hdr.rtm_addrs & (1 << RTAX_NETMASK) != 0 {
        match route_addresses[RTAX_NETMASK as usize] {
            None => prefix = 0,
            // Yes, apparently a 0 prefixlen is encoded as having an sa_len of 0
            // (at least in some cases).
            Some(sa) if sa.sa_len == 0 => prefix = 0,
            Some(sa) => match destination {
                IpAddr::V4(_) => {
                    let mask_sa: &sockaddr_in = unsafe { mem::transmute(sa) };
                    prefix = u32::from_be(mask_sa.sin_addr.s_addr).leading_ones() as u8;
                }
                IpAddr::V6(_) => {
                    let mask_sa: &sockaddr_in6 = unsafe { mem::transmute(sa) };
                    // sin6_addr.__u6_addr is a union that represents the 16 v6 bytes either as
                    // 16 u8's or 16 u16's or 4 u32's. So we need the unsafe here because of the union
                    prefix = u128::from_be_bytes(unsafe { mask_sa.sin6_addr.__u6_addr.__u6_addr8 })
                        .leading_ones() as u8;
                }
            },
        }
    }

    Some(Route {
        destination,
        prefix,
        gateway,
        if_name: if_index_to_name(hdr.rtm_index as u32).ok(),
        if_index: Some(hdr.rtm_index as u32),
    })
}
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
struct m_rtmsg {
    hdr: rt_msghdr,
    attrs: [u8; 512],
}
impl m_rtmsg {
    pub(crate) fn slice(&self) -> &[u8] {
        let slice = {
            let ptr = self as *const m_rtmsg as *const u8;
            let len = self.hdr.rtm_msglen as usize;
            unsafe { std::slice::from_raw_parts(ptr, len) }
        };
        slice
    }
}
impl Default for sockaddr_dl {
    fn default() -> Self {
        let mut sdl: sockaddr_dl = unsafe { mem::zeroed() };
        sdl.sdl_len = std::mem::size_of::<Self>() as u8;
        sdl.sdl_family = AF_LINK as u8;
        sdl
    }
}
impl Default for rt_metrics {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}
impl Default for rt_msghdr {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

fn sa_to_ip(sa: &sockaddr) -> Option<IpAddr> {
    match sa.sa_family as u32 {
        AF_INET => {
            assert!(sa.sa_len as usize >= std::mem::size_of::<sockaddr_in>());
            let inet: &sockaddr_in = unsafe { std::mem::transmute(sa) };
            let octets: [u8; 4] = inet.sin_addr.s_addr.to_ne_bytes();
            Some(IpAddr::from(octets))
        }
        AF_INET6 => {
            assert!(sa.sa_len as usize >= std::mem::size_of::<sockaddr_in6>());
            let inet6: &sockaddr_in6 = unsafe { mem::transmute(sa) };
            let octets: [u8; 16] = unsafe { inet6.sin6_addr.__u6_addr.__u6_addr8 };
            Some(IpAddr::from(octets))
        }
        AF_LINK => None,
        _ => None,
    }
}
impl From<Ipv4Addr> for sockaddr_in {
    fn from(ip: Ipv4Addr) -> Self {
        let sa_len = std::mem::size_of::<sockaddr_in>();
        sockaddr_in {
            sin_len: sa_len as u8,
            sin_family: AF_INET as u8,
            sin_port: 0,
            sin_addr: in_addr {
                s_addr: u32::from_ne_bytes(ip.octets()),
            },
            sin_zero: [0i8; 8],
        }
    }
}
impl From<Ipv6Addr> for sockaddr_in6 {
    fn from(ip: Ipv6Addr) -> Self {
        let sa_len = std::mem::size_of::<sockaddr_in6>();
        sockaddr_in6 {
            sin6_len: sa_len as u8,
            sin6_family: AF_INET6 as u8,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: in6_addr {
                __u6_addr: unsafe {
                    mem::transmute::<[u8; 16], in6_addr__bindgen_ty_1>(ip.octets())
                },
            },
            sin6_scope_id: 0,
        }
    }
}
fn create_route_socket() -> io::Result<UnixStream> {
    let fd = unsafe { socket(PF_ROUTE as i32, SOCK_RAW as i32, AF_UNSPEC as i32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let route_fd = unsafe { UnixStream::from_raw_fd(fd) };
    Ok(route_fd)
}
