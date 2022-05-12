#![no_std]
#![no_main]

use core::mem::{size_of, transmute};
// use memoffset::offset_of;
use redbpf_probes::xdp::prelude::*;

use probes::xdp::csum::*;
use probes::xdp::{ClientInfo, LocalInfo};

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps/c2l")]
static mut C2L: HashMap<ClientInfo, LocalInfo> = HashMap::with_max_entries(8);

#[map(link_section = "maps/l2c")]
static mut L2C: HashMap<LocalInfo, ClientInfo> = HashMap::with_max_entries(1200000);

#[map(link_section = "maps/dst")]
static mut DST: LruHashMap<[u16; 5], [u16; 5]> = LruHashMap::with_max_entries(1024);

static mut LPORT: u16 = 44444;

fn process_eth(ethh: *mut ethhdr, new_src: [u8; 6], new_dst: [u8; 6]) {
    unsafe {
        (*ethh).h_source = new_src;
        (*ethh).h_dest = new_dst;
    }
}

fn process_l3(iph: *mut iphdr, new_saddr: u32, new_daddr: u32) {
    unsafe {
        _ = printk!("protocol: %x", (*iph).protocol);
        (*iph).saddr = new_saddr;
        (*iph).daddr = new_daddr;
    }

    // csum
    unsafe {
        // _ = printk!("original l3 csum: %x", (*iph).check);
        (*iph).check = 0;
    }
    let mut csum = 0_u64;

    csum_ipv4(iph, &mut csum);
    // _ = printk!("new l3 csum: %lu -> %x", csum, csum as u16);
    unsafe {
        (*iph).check = csum as u16;
    }
}

fn process_l4_tcp(
    tcph: *mut tcphdr,
    old_saddr: u32,
    old_daddr: u32,
    iph: *mut iphdr,
    new_saddr: u32,
    new_daddr: u32,
    new_src_port: u16,
    new_dst_port: u16,
) {
    unsafe {
        const DEBUG_CSUM: bool = true;
        const NWORD: usize = size_of::<tcphdr>() / size_of::<u16>();
        let old_bytes = transmute::<tcphdr, [u16; NWORD]>(*tcph);
        if DEBUG_CSUM {
            _ = printk!("old tcp");
            for b in old_bytes {
                _ = printk!("b: %x", b);
            }
        }

        // _ = printk!("src: %d dest: %d", new_src, new_dst);
        (*tcph).source = new_src_port;
        (*tcph).dest = new_dst_port;

        //// csum
        let mut csum = (*tcph).check;
        let bytes = transmute::<tcphdr, [u16; NWORD]>(*tcph);
        if DEBUG_CSUM {
            _ = printk!("new tcp");
            for b in bytes {
                _ = printk!("b: %x", b);
            }
        }

        let tcplen = ((*iph).tot_len.swap_bytes() - (((*iph).ihl() << 2) as u16)).to_be();
        
        _ = printk!("kern: old_saddr: %x", old_saddr);
        _ = printk!("kern: old_daddr: %x", old_daddr);
        // psudo header
        let old_psudo_header: [u16; 6] = [
            (old_saddr & 0xffff) as u16, // saddr lower 16bit 
            ((old_saddr >> 16) & 0xffff) as u16,
            (old_daddr & 0xffff) as u16,
            ((old_daddr >> 16) & 0xffff) as u16,
            0b110,
            tcplen,
        ];
        let new_psudo_header: [u16; 6] = [
            (new_saddr  & 0xffff) as u16,
            ((new_saddr >> 16) & 0xffff) as u16,
            (new_daddr  & 0xffff) as u16,
            ((new_daddr >> 16) &0xffff) as u16,
            0b110,
            tcplen,
        ];
        for (i, b) in new_psudo_header.iter().enumerate() {
            if *b != old_psudo_header[i] {
                if DEBUG_CSUM {
                    _ = printk!(
                        "psudo_header: bytes %d %x differs from %x",
                        i as i32,
                        *b,
                        old_psudo_header[i]
                    );
                }
                csum = csum_ipv4_l4(csum, old_psudo_header[i], *b);
            } else {
                _ = printk!("psudo_header: bytes %d %x", i as i32, *b);
            }
        }

        // // saddr
        // csum = csum_ipv4_l4(
        //     csum,
        //     (old_saddr << 16 & 0xffff) as u16,
        //     // 0,
        //     (new_saddr << 16 & 0xffff) as u16,
        // );
        // csum = csum_ipv4_l4(
        //     csum,
        //     (old_saddr >> 16) as u16,
        //     // 0,
        //     (new_saddr >> 16) as u16,
        // );

        // // daddr
        // csum = csum_ipv4_l4(
        //     csum,
        //     (old_daddr << 16 & 0xffff) as u16,
        //     // 0,
        //     (new_daddr << 16 & 0xffff) as u16,
        // );
        // csum = csum_ipv4_l4(
        //     csum,
        //     (old_daddr >> 16) as u16,
        //     // 0,
        //     (new_daddr >> 16) as u16,
        // );

        // protocol
        // csum = csum_ipv4_l4(csum, 0, 6);

        // len
        // _ = printk!("tot_len: %d, ihl: %d", (*iph).tot_len.swap_bytes(), (*iph).ihl());
        // _ = printk!("ihl << 2: %d", (*iph).ihl() << 2);
        // _ = printk!("calculated tcp len: %d", tcplen);
        // csum = csum_ipv4_l4(csum, 0, tcplen);

        for (i, b) in bytes.iter().enumerate() {
            if *b != old_bytes[i] {
                if DEBUG_CSUM {
                    _ = printk!("bytes %d %x differs from %x", i as i32, *b, old_bytes[i]);
                }
                csum = csum_ipv4_l4(csum, old_bytes[i], *b);
            }
        }
        // _ = printk!("new_csum %x", csum);

        (*tcph).check = csum;
    }
}

#[xdp]
pub fn kern(ctx: XdpContext) -> XdpResult {
    let iph = match ctx.ip_mut() {
        Ok(ip) => ip,
        Err(_) => {
            // printk!("not ip");
            return Ok(XdpAction::Pass);
        }
    };

    unsafe {
        match ctx.transport_mut() {
            Err(_) => {
                _ = printk!("failed to get transport");
                return Ok(XdpAction::Pass);
            }

            Ok(t) => {
                match t {
                    TransportMut::TCP(tcph) => {
                        // client
                        let cip = (*iph).saddr;
                        let cport = (*tcph).source;
                        let cdaddr = (*iph).daddr;
                        let cdport = (*tcph).dest;

                        // virtual
                        // let vip = u32::from_be_bytes([127, 0, 0, 42]).to_be();
                        let vip = u32::from_be_bytes([10, 13, 148, 51]).to_be();
                        let vport = 42;

                        // rs
                        // let rip = u32::from_be_bytes([10, 13, 148, 51]).to_be(); // local
                        let rip = u32::from_be_bytes([10, 13, 5, 33]).to_be(); // vm
                                                                               // let rip = u32::from_be_bytes([10, 13, 144, 139]).to_be(); // genhao
                        let rport = 80_u16.swap_bytes();

                        // local
                        let lip = u32::from_be_bytes([10, 13, 148, 51]).to_be();

                        if (*iph).daddr == vip && t.dest() == vport {
                            _ = printk!("hit rule");
                            _ = printk!("kern: cip: %x", cip);

                            let clientinfo = &mut ClientInfo::new();
                            clientinfo.ip = cip;
                            clientinfo.port = cport;
                            
                            let localinfo = &mut LocalInfo::new();

                            let (lip, lport) = if (*tcph).syn() > 0 && !(*tcph).ack() > 0 {
                                let lport  = u16::from(LPORT).to_be();
                                LPORT = LPORT + 1;

                                localinfo.ip = lip;
                                localinfo.port = lport;

                                C2L.set(&clientinfo.clone(), &localinfo.clone());
                                L2C.set(&localinfo.clone(), &clientinfo.clone());

                                (lip, lport)
                            } else {
                                match C2L.get(&clientinfo.clone()) {
                                    Some(li) => (li.ip, li.port),
                                    None => return Ok(XdpAction::Drop),
                                }
                            };

                            _ = printk!("kern: local port: %d", lport.swap_bytes());

                            // process eth hdr
                            let ethh = match ctx.eth_mut() {
                                Ok(ethhdr) => ethhdr,
                                Err(_) => return Ok(XdpAction::Aborted),
                            };

                            process_eth(ethh, (*ethh).h_dest, [0x0, 0x0, 0x0, 0x0, 0x0, 0x01]);
                            process_l3(iph, lip, rip);
                            process_l4_tcp(tcph, cip, vip, iph, lip, rip, lport, rport);

                            return Ok(XdpAction::Tx);
                        }

                        // rs -> local -> client
                        if (*iph).daddr == lip {
                            let mut localinfo = LocalInfo::new();
                            localinfo.ip = lip;
                            localinfo.port = cdport;
                            let clientinfo = match L2C.get(&localinfo) {
                                Some(v) => v,
                                None => return Ok(XdpAction::Pass),
                            };
                            // _ = printk!("client ip: %x, client port: %d", clientinfo.ip, clientinfo.port);

                            _ = printk!("hit local!!");
                            _ = printk!("local port %d", cdport.swap_bytes());

                            // process eth hdr
                            let ethh = match ctx.eth_mut() {
                                Ok(ethhdr) => ethhdr,
                                Err(_) => return Ok(XdpAction::Drop),
                            };
                            process_eth(ethh, (*ethh).h_dest, [0x0, 0x0, 0x0, 0x0, 0x0, 0x01]);
                            process_l3(iph, vip, clientinfo.ip);
                            process_l4_tcp(
                                tcph,
                                rip,
                                lip,
                                iph,
                                vip,
                                clientinfo.ip,
                                vport.to_be(),
                                clientinfo.port,
                            );
                            _ = printk!("local tx");

                            return Ok(XdpAction::Tx);
                        }

                        if (*iph).saddr == rip && (*tcph).dest != 32987 && (*tcph).dest != 35555 {
                            _ = printk!("?????");
                            _ = printk!("dst ip: %x", (*iph).daddr);
                            // _ = printk!("lport(44444 be) %x(%u)", lport, lport);
                            _ = printk!("from rs: dport: %x(%u)", (*tcph).dest, (*tcph).dest);
                            _ = printk!(
                                "to_le: %x(%u)",
                                (*tcph).dest.swap_bytes(),
                                (*tcph).dest.swap_bytes()
                            );
                        }
                        return Ok(XdpAction::Pass);
                    }
                    TransportMut::UDP(_udp) => {
                        // t::UDP
                        return Ok(XdpAction::Pass);
                    }
                }
            }
        }
    };

    // Ok(XdpAction::Pass)
}
