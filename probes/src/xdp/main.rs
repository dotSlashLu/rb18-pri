#![no_std]
#![no_main]

use core::mem::{size_of, transmute};
use memoffset::offset_of;
use redbpf_probes::xdp::prelude::*;

use probes::xdp::csum::*;
use probes::xdp::{ClientInfo, LocalInfo};

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps/c2l")]
static mut C2L: HashMap<ClientInfo, LocalInfo> = HashMap::with_max_entries(8);

#[map(link_section = "maps/l2c")]
static mut L2C: HashMap<LocalInfo, ClientInfo> = HashMap::with_max_entries(8);

#[map(link_section = "maps/dst")]
static mut DST: LruHashMap<[u16; 5], [u16; 5]> = LruHashMap::with_max_entries(1024);

fn process_eth(ethh: *mut ethhdr, new_src: [u8; 6], new_dst: [u8; 6]) {
    unsafe {
        (*ethh).h_source = new_src;
        (*ethh).h_dest = new_dst;
    }
}

fn process_l3(iph: *mut iphdr, new_saddr: u32, new_daddr: u32) {
    unsafe {
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

fn process_l4_tcp(tcph: *mut tcphdr, new_src: u16, new_dst: u16) {
    unsafe {
        const NWORD: usize = size_of::<tcphdr>() / size_of::<u16>();
        let old_bytes = transmute::<tcphdr, [u16; NWORD]>(*tcph);

        // _ = printk!("src: %d dest: %d", new_src, new_dst);
        (*tcph).source = new_src;
        (*tcph).dest = new_dst;

        //// csum
        let mut csum = (*tcph).check;
        let bytes = transmute::<tcphdr, [u16; NWORD]>(*tcph);
        // _ = printk!("new tcp");
        // for b in bytes {
        //     _ = printk!("b: %x", b);
        // }

        for (i, b) in bytes.iter().enumerate() {
            if *b != old_bytes[i] {
                // _ = printk!("bytes %d %x differs from %x", i as i32, *b, old_bytes[i]);
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
            Ok(t) => match t {
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

                    // local
                    let lip = u32::from_be_bytes([10, 13, 148, 51]).to_be();
                    // let lport: u16 = u16::from(44444_u16).to_be();
                    let lport: u16 = u16::from(44444_u16).to_be();

                    // rs
                    // let rip = u32::from_be_bytes([10, 13, 148, 51]).to_be(); // local
                    let rip = u32::from_be_bytes([10, 13, 5, 33]).to_be(); // vm
                    let rport = 80_u16.swap_bytes();

                    let client_ip = transmute::<u32, [u8; 4]>((*iph).saddr);
                    let mut k: [u16; 5] = [0; 5];
                    for i in 0..4 {
                        k[i] = client_ip[i] as u16
                    }
                    k[4] = cport;

                    let dip = transmute::<u32, [u8; 4]>(cdaddr);
                    let mut v: [u16; 5] = [0; 5];
                    for i in 0..4 {
                        v[i] = dip[i] as u16;
                    }
                    v[4] = t.dest();
                    DST.set(&k, &v);

                    // let mut msg = [0u8; 6];
                    // for i in 0..4 {
                    //     msg[i] = msg_ip[i];
                    // }
                    // bpf_trace_printk(&msg[0..5]);

                    if (*iph).daddr == vip && t.dest() == vport {
                        _ = printk!("hit rule");

                        // _ = printk!("old tcp");
                        // for b in old_bytes {
                        //     _ = printk!("b: %x", b);
                        // }

                        let mut localinfo = LocalInfo::new();
                        localinfo.ip = lip;
                        localinfo.port = lport;
                        let localinfo = &localinfo;

                        let mut clientinfo = ClientInfo::new();
                        clientinfo.ip = cip;
                        clientinfo.port = cport;
                        let clientinfo = &clientinfo;

                        C2L.set(&clientinfo.clone(), &localinfo.clone());
                        L2C.set(&localinfo.clone(), &clientinfo.clone());

                        // process eth hdr
                        let ethh = match ctx.eth_mut() {
                            Ok(ethhdr) => ethhdr,
                            Err(_) => return Ok(XdpAction::Aborted),
                        };

                        process_eth(ethh, (*ethh).h_dest, [0x0, 0x0, 0x0, 0x0, 0x0, 0x01]);
                        process_l3(iph, lip, rip);
                        process_l4_tcp(tcph, lport, rport);

                        return Ok(XdpAction::Tx);
                    }

                    // rs -> local
                    if (*tcph).dest == lport {
                        _ = printk!("hit local!!");
                        let mut localinfo = LocalInfo::new();
                        localinfo.ip = lip;
                        localinfo.port = lport;
                        let clientinfo = match L2C.get(&localinfo) {
                            Some(v) => v,
                            None => return Ok(XdpAction::Drop),
                        };
                        // _ = printk!("client ip: %x, client port: %d", clientinfo.ip, clientinfo.port);

                        // process eth hdr
                        let ethh = match ctx.eth_mut() {
                            Ok(ethhdr) => ethhdr,
                            Err(_) => return Ok(XdpAction::Drop),
                        };
                        process_eth(ethh, (*ethh).h_dest, [0x0, 0x0, 0x0, 0x0, 0x0, 0x01]);
                        process_l3(iph, vip, clientinfo.ip);
                        process_l4_tcp(tcph, vport.to_be(), clientinfo.port);
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
            },
            Err(_) => {
                bpf_trace_printk(b"failed to get transport\0");
                return Ok(XdpAction::Pass);
            }
        }
    };

    // Ok(XdpAction::Pass)
}
