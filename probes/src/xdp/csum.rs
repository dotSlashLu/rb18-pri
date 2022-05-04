#![no_std]
#![no_main]

use core::convert::TryInto;
use core::mem::{size_of, transmute};
use memoffset::offset_of;
use redbpf_probes::xdp::prelude::*;

const MAX_TCP_LENGTH: usize = 1480;

// __attribute__((__always_inline__)) static inline __u16 csum_fold_helper(
//     __u64 csum) {
//   int i;
// #pragma unroll
//   for (i = 0; i < 4; i++) {
//     if (csum >> 16)
//       csum = (csum & 0xffff) + (csum >> 16);
//   }
//   return ~csum;
// }
#[inline]
fn csum_fold(mut csum: u64) -> u64 {
    for _i in 0..4 {
        if csum >> 16 != 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    let res = !csum;
    printk!("folded: %lu", res);
    res
}

// __attribute__((__always_inline__)) static inline void ipv4_csum_inline(
//     void* iph,
//     __u64* csum) {
//   __u16* next_iph_u16 = (__u16*)iph;
// #pragma clang loop unroll(full)
//   for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
//     *csum += *next_iph_u16++;
//   }
//   *csum = csum_fold_helper(*csum);
// }
#[inline]
pub fn csum_ipv4(ip_header: *mut iphdr, mut csum: *mut u64) {
    let hdr = ip_header as *mut u16;
    let sizeof_iphdr = size_of::<iphdr>();
    let slice = unsafe { core::slice::from_raw_parts(hdr, sizeof_iphdr >> 1) };
    unsafe {
        for i in slice {
            *csum += *i as u64;
        }
    }
    unsafe { *csum = csum_fold(*csum) }
}

// __attribute__((__always_inline__)) static inline void
// ipv4_l4_csum(void* data_start, int data_size, __u64* csum, struct iphdr* iph) {
//   __u32 tmp = 0;
//   *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
//   *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
//   tmp = __builtin_bswap32((__u32)(iph->protocol));
//   *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
//   tmp = __builtin_bswap32((__u32)(data_size));
//   *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
//   *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
//   *csum = csum_fold_helper(*csum);
// }
//
// ipv4_l4_csum(udp, udp_len, &cs, iph) ;
#[inline]
pub fn csum_ipv4_l4(data_start: *mut u32, data_size: usize, csum: *mut u64, iph: *mut iphdr) {
    // let mut tmp = &mut 0_u32 as *mut u32;
    let size_u32 = size_of::<u32>() as u32;

    let zero = &mut 0;
    let saddr = unsafe { &mut (*iph).saddr as *mut u32 };
    let daddr = unsafe { &mut (*iph).daddr as *mut u32 };
    // let csumv = unsafe {*csum};
    // let mut csumv = 0;

    unsafe {
        //   *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
        // *csum = bpf_csum_diff(zero, 0, saddr, size_u32, csumv as u32) as u64;
        *csum = bpf_csum_diff(&mut 0, 0, saddr, size_u32, *csum as u32) as u64;

        //   *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
        // *csum = bpf_csum_diff(zero, 0, daddr, size_u32, csumv as u32) as u64;
        *csum = bpf_csum_diff(&mut 0, 0, daddr, size_u32, *csum as u32) as u64;
        //   tmp = __builtin_bswap32((__u32)(iph->protocol));
        let mut tmp = u32::from((*iph).protocol).to_be();

        //   *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
        *csum = bpf_csum_diff(&mut 0, 0, &mut tmp, size_u32, *csum as u32) as u64;

        //   tmp = __builtin_bswap32((__u32)(data_size));
        tmp = (data_size as u32).to_be();

        //   *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
        *csum = bpf_csum_diff(&mut 0, 0, &mut tmp, size_u32, *csum as u32) as u64;

        *csum = bpf_csum_diff(&mut 0, 0, &mut tmp, size_u32, *csum as u32) as u64;

        //   *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
        *csum = bpf_csum_diff(&mut 0, 0, data_start, data_size as u32, *csum as u32) as u64;

        //   *csum = csum_fold_helper(*csum);
        *csum = csum_fold(*csum);
    }
}

// #[inline]
// fn csum_ipv4_l4_with_port(tcph: *mut tcphdr, data_size: usize, csum: *mut u64, iph: *mut iphdr) {
//     // let mut tmp = &mut 0_u32 as *mut u32;
//     let size_u32 = size_of::<u32>() as u32;
//
//     let zero = &mut 0;
//     let saddr = unsafe { &mut (*iph).saddr as *mut u32 };
//     let daddr = unsafe { &mut (*iph).daddr as *mut u32 };
//     // let csumv = unsafe {*csum};
//     // let mut csumv = 0;
//
//     unsafe {
//         //   *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
//         // *csum = bpf_csum_diff(zero, 0, saddr, size_u32, csumv as u32) as u64;
//         *csum = bpf_csum_diff(&mut 0, 0, saddr, size_u32, *csum as u32) as u64;
//
//         //   *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
//         // *csum = bpf_csum_diff(zero, 0, daddr, size_u32, csumv as u32) as u64;
//         *csum = bpf_csum_diff(&mut 0, 0, daddr, size_u32, *csum as u32) as u64;
//         //   tmp = __builtin_bswap32((__u32)(iph->protocol));
//         let mut tmp = u32::from((*iph).protocol).to_be();
//
//         //   *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
//         *csum = bpf_csum_diff(&mut 0, 0, &mut tmp, size_u32, *csum as u32) as u64;
//
//         // sport
//         *csum = bpf_csum_diff(&mut 0, 0, &mut tmp, size_u32, *csum as u32) as u64;
//
//         // data_size
//         // tmp = __builtin_bswap32((__u32)(data_size));
//         tmp = (data_size as u32).to_be();
//         //   *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
//         *csum = bpf_csum_diff(&mut 0, 0, &mut tmp, size_u32, *csum as u32) as u64;
//
//
//         //   *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
//         *csum = bpf_csum_diff(&mut 0, 0, data_start, data_size as u32, *csum as u32) as u64;
//
//         //   *csum = csum_fold_helper(*csum);
//         *csum = csum_fold(*csum);
//     }
// }

// #[inline]
// fn csum_ipv4_l4_3(csum: u64, iph: *mut iphdr) {
//     let size_u32 = size_of::<u32>() as u32;
//
//     let zero = &mut 0;
//     let saddr = unsafe { &mut (*iph).saddr as *mut u32 };
//     let daddr = unsafe { &mut (*iph).saddr as *mut u32 };
//     let csumv = 0;
//
//     unsafe {
//         // pushes saddr
//         // *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
//         *csum = bpf_csum_diff(&mut 0, 0, saddr, size_u32, csumv as u32) as u64;
//
//         // pushes daddr
//         // *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
//         *csum = bpf_csum_diff(&mut 0, 0, daddr, size_u32, csumv as u32) as u64;
//
//         // tmp = __builtin_bswap32((__u32)(data_size));
//         tmp = &mut (data_len as u32) as *mut u32;
//
//         // pushes data_len
//         // *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
//         *csum = bpf_csum_diff(&mut 0, 0, tmp, size_u32, csumv as u32) as u64;
//
//         // pushes whole hdr?
//         // *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
//         *csum = bpf_csum_diff(&mut 0, 0, data_start, data_len as u32, csumv as u32) as u64;
//
//         // *csum = csum_fold_helper(*csum);
//         *csum = csum_fold(csumv);
//     }
// }

#[inline]
pub fn csum_ipv4_l4_2(csum: u64, o: u32, n: u32) -> u64 {
    // ~HC
    let mut csum = !csum;
    csum = csum & 0xffff;

    let tmp = !o;
    csum += tmp as u64;
    csum += n as u64;
    csum = csum_fold(csum);
    csum

    // *csum = *csum & 0xffff;
    // // + ~m
    // __u32 tmp;
    // tmp = ~old_addr;
    // *csum += tmp;
    // // + m
    // *csum += new_addr;
    // // then fold and complement result !
    // *csum = csum_fold_helper(*csum);
}

#[inline]
pub fn csum_ipv4_l4_4(csum: u32, o: u32, n: u32) -> u32 {
    // sum = old_daddr + (~ntohs(*(unsigned short *)&iph->daddr) & 0xffff);
    let mut sum = o + (!n.to_le()) & 0xffff;
    // sum += ntohs(tcph->check);
    sum += csum.to_le();
    // sum = (sum & 0xffff) + (sum>>16);
    sum = (sum & 0xffff) + (sum >> 16);
    // tcph->check = htons(sum + (sum>>16) - 1);
    sum = sum + (sum >> 16) - 1;
    sum.to_be().into()
}

#[inline]
pub fn csum_ipv4_l4_5_word(csum: u16, o: u32, n: u32) -> u16 {
    let o_words = unsafe { transmute::<u32, [u16; 2]>(o) };
    let n_words = unsafe { transmute::<u32, [u16; 2]>(n) };

    let csum = csum_ipv4_l4_5(csum, o_words[0], n_words[0]);
    csum_ipv4_l4_5(csum, o_words[1], n_words[1])
}

#[inline]
pub fn csum_ipv4_l4_5(csum: u16, o: u16, n: u16) -> u16 {
    // HC  - old checksum in header
    // C   - one's complement sum of old header
    // HC' - new checksum in header
    // C'  - one's complement sum of new header
    // m   - old value of a 16-bit field
    // m'  - new value of a 16-bit field

    // HC' = ~(C + (-m) + m')    --    [Eqn. 3]
    // = ~(~HC + ~m + m')

    !(!csum + !o + n)
}

#[inline]
pub fn csum_ipv4_l4_6(csum: u16, o: u32, n: u32) -> u16 {
    printk!("csum %x o %x n %x", csum, o, n);
    let mut sum = o + (!n.to_le() & 0xffff);
    printk!("1. %x", sum);
    sum += csum as u32;
    printk!("2. %x", sum);
    sum = (sum & 0xffff) + (sum >> 16);
    printk!("3. %x", sum);
    let res = ((sum + (sum >> 16) - 1) as u16).to_be();
    printk!("4. %x", res);
    res
}