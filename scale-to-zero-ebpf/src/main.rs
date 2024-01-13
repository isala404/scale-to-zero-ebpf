#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use scale_to_zero_common::PacketLog;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static SCALE_REQUESTS: PerfEventArray<PacketLog> =
    PerfEventArray::with_max_entries(1024, 0);

#[map]
static SERVICE_LIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_scale_to_zero_fw(ctx: XdpContext) -> u32 {
    match try_xdp_scale_to_zero_fw(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

// 
fn is_scalable_dst(address: u32) -> bool {
    unsafe { SERVICE_LIST.get(&address).is_some() }
}

fn try_xdp_scale_to_zero_fw(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let dst = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let action = if is_scalable_dst(dst) {
        let log_entry = PacketLog {
            ipv4_address: dst,
            action: 1,
        };
        SCALE_REQUESTS.output(&ctx, &log_entry, 0);
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };
    Ok(action)
}
