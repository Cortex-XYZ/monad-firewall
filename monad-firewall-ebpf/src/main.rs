#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpError, IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // Ethernet IEEE 802.3 Frame Format / Structure:
    // https://www.electronics-notes.com/articles/connectivity/ethernet-ieee-802-3/data-frames-structure-format.php
    // https://en.wikipedia.org/wiki/Ethernet_frame
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    let eth_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    if eth_type != EtherType::Ipv4 as u16 {
        return Ok(xdp_action::XDP_DROP);
    }

    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    let proto = unsafe { (*ipv4hdr).proto() }.map_err(|IpError::InvalidProto(_proto)| ())?;

    let source_port = match proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be_bytes(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe { (*udphdr).src_port() }
        }
        _ => return Err(()),
    };

    info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);

    Ok(xdp_action::XDP_PASS)
}
