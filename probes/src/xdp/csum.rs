use core::mem::size_of;
use redbpf_probes::xdp::prelude::*;

#[inline]
pub fn csum_fold(mut csum: u64) -> u64 {
    for _i in 0..4 {
        if csum >> 16 != 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    let res = !csum;
    // _ = printk!("folded: %lu", res);
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
pub fn csum_ipv4(ip_header: *mut iphdr, csum: *mut u64) {
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

// https://datatracker.ietf.org/doc/html/rfc1624
#[inline]
pub fn csum_ipv4_l4(csum: u16, o: u16, n: u16) -> u16 {
    // HC  - old checksum in header
    // C   - one's complement sum of old header
    // HC' - new checksum in header
    // C'  - one's complement sum of new header
    // m   - old value of a 16-bit field
    // m'  - new value of a 16-bit field

    // HC' = ~(C + (-m) + m')
    // = HC + (m - m')
    // = HC + m + ~m'    --    [Eqn. 2]

    // HC' = ~(C + (-m) + m')    --    [Eqn. 3]
    // = ~(~HC + ~m + m')

    // csum + o + !n
    !(!csum + !o + n) - 1
}
