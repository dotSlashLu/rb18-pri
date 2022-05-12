use core::mem::size_of;
use redbpf_probes::xdp::prelude::*;

const RTE_IPV4_HDR_IHL_MASK: u8 = 0x0f;
const RTE_IPV4_IHL_MULTIPLIER: u8 = 4;

pub unsafe fn rte_ipv4_hdr_len(ipv4_hdr: *const iphdr) -> u8 {
    let tmp = (((*ipv4_hdr).ihl() & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER) as u8;
    _ = printk!("csum_dpdk: ipv4_hdr_len: %d", tmp);
    tmp
}

unsafe fn rte_ipv4_phdr_cksum(iph: *const iphdr) -> u16 {
    #[repr(C)]
    struct IPV4_PSD_HEADER {
        src_addr: u32,
        dst_addr: u32,
        zero: u8,
        proto: u8,
        len: u16,
    }

    // XXX: endianness?
    let l4_len: u16 = ((*iph).tot_len.swap_bytes() - rte_ipv4_hdr_len(iph) as u16).to_be();
    // let l4_len: u16 = ((*iph).tot_len.swap_bytes() - rte_ipv4_hdr_len(iph) as u16);
    _ = printk!("csum_dpdk: l4_len: %x", l4_len);

    let psd_hdr = IPV4_PSD_HEADER {
        src_addr: (*iph).saddr,
        dst_addr: (*iph).daddr,
        zero: 0,
        proto: (*iph).protocol,
        len: l4_len,
    };

    rte_raw_cksum(&psd_hdr, size_of::<IPV4_PSD_HEADER>() as u32)
}

// XXX: if len is odd
fn __rte_raw_cksum<T>(buf: *const T, _len: u32, sum: u32) -> u32 {
    let hdr = buf as *const u16;
    let sizeof_hdr = size_of::<T>();
    let slice = unsafe { core::slice::from_raw_parts(hdr, sizeof_hdr >> 1) };
    let mut sum = sum;
    for i in slice {
        _ = printk!("csum_dpdk: buf: %x", *i);
        sum += *i as u32;
    }
    sum
}

fn __rte_raw_cksum_reduce(sum: u32) -> u16 {
    let mut sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum as u16
}

fn rte_raw_cksum<T>(l4_hdr: *const T, l4_len: u32) -> u16 {
    let sum = __rte_raw_cksum(l4_hdr, l4_len, 0);
    __rte_raw_cksum_reduce(sum)
}

#[inline]
pub fn rte_ipv4_udptcp_csum(ipv4_hdr: *const iphdr, tcp_hdr: *const tcphdr) -> u16 {
    let mut cksum = unsafe { __rte_ipv4_udptcp_csum(ipv4_hdr, tcp_hdr) };
    cksum = !cksum;

    unsafe {
        if cksum == 0 && (*ipv4_hdr).protocol == IPPROTO_UDP as u8 {
            cksum = 0xffff;
        }
    }

    cksum
}

#[inline]
unsafe fn __rte_ipv4_udptcp_csum(ipv4_hdr: *const iphdr, tcp_hdr: *const tcphdr) -> u16 {
    let ip_hdr_len: u8 = rte_ipv4_hdr_len(ipv4_hdr);
    _ = printk!(
        "csum_dpdk: tot_len: %d, swapped: %d",
        (*ipv4_hdr).tot_len,
        (*ipv4_hdr).tot_len.swap_bytes()
    );
    let l3_len: u32 = (*ipv4_hdr).tot_len.swap_bytes() as u32;
    let l4_len: u32 = l3_len - ip_hdr_len as u32;
    let mut cksum: u32 = rte_raw_cksum(tcp_hdr, l4_len) as u32;
    cksum += rte_ipv4_phdr_cksum(ipv4_hdr) as u32;
    cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
    cksum as u16
}
