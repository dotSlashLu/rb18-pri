#![no_std]
#![no_main]

use core::convert::TryInto;
use core::mem::{size_of, transmute};
use memoffset::offset_of;
use redbpf_probes::xdp::prelude::*;

use probes::xdp::{ClientInfo, LocalInfo};
use probes::xdp::csum::*;

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps/c2l")]
static mut C2L: HashMap<ClientInfo, LocalInfo> = HashMap::with_max_entries(8);

#[map(link_section = "maps/l2c")]
static mut L2C: HashMap<LocalInfo, ClientInfo> = HashMap::with_max_entries(8);

#[map(link_section = "maps/dst")]
static mut DST: LruHashMap<[u16; 5], [u16; 5]> = LruHashMap::with_max_entries(1024);

#[xdp]
pub fn kern(ctx: XdpContext) -> XdpResult {
    let ip = match ctx.ip_mut() {
        Ok(ip) => ip,
        Err(_) => {
            // printk!("not ip");
            return Ok(XdpAction::Pass);
        }
    };

    unsafe {
        match ctx.transport_mut() {
            Ok(t) => match t {
                TransportMut::TCP(tcp) => {
                    // client
                    let cip = (*ip).saddr;
                    let cport = (*tcp).source;
                    let cdaddr = (*ip).daddr;
                    let cdport = (*tcp).dest;

                    // virtual
                    // let vip = u32::from_be_bytes([127, 0, 0, 42]).to_be(); // 127.0.0.42
                    let vip = u32::from_be_bytes([10, 13, 148, 51]).to_be(); // 127.0.0.42
                    let vport = 42;

                    // local
                    let lip = u32::from_be_bytes([10, 13, 148, 51]).to_be(); // 10.13.148.51
                    let lport: u16 = u16::from(44444_u16).to_be();

                    // rs
                    // let rip = u32::from_be_bytes([10, 13, 148, 51]).to_be(); // local
                    let rip = u32::from_be_bytes([10, 13, 5, 33]).to_be(); // vm
                    let rport = 80_u16.to_be();

                    let client_ip = transmute::<u32, [u8; 4]>((*ip).saddr);
                    let mut k: [u16; 5] = [0; 5];
                    for i in 0..4 {
                        k[i] = client_ip[i] as u16
                    }
                    k[4] = t.source();

                    let dip = transmute::<u32, [u8; 4]>((*ip).daddr);
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

                    if (*ip).daddr == vip && t.dest() == vport {
                        printk!("hit rule");
                        let saddr = (*ip).saddr;

                        let mut localinfo = LocalInfo::new();
                        localinfo.ip = lip;
                        localinfo.port = lport;
                        let localinfo = &localinfo;

                        let mut clientinfo = ClientInfo::new();
                        clientinfo.ip = saddr;
                        clientinfo.port = t.source();
                        let clientinfo = &clientinfo;

                        C2L.set(&clientinfo.clone(), &localinfo.clone());
                        L2C.set(localinfo, clientinfo);

                        // process eth hdr
                        let mut ethhdr = match ctx.eth_mut() {
                            Ok(ethhdr) => ethhdr,
                            Err(_) => return Ok(XdpAction::Aborted),
                        };
                        // let mut msg: [u8; 7] = [0; 7];
                        // for i in 0..6 {
                        //     msg[i] = (*ethhdr).h_dest[i];
                        //     printk!("%d", msg[i]);
                        // }
                        // msg[6] = b'\0';
                        // bpf_trace_printk(&msg);
                        (*ethhdr).h_source = (*ethhdr).h_dest;
                        // 74:ea:c8:42:f2:01
                        // what is the endianess?
                        // (*ethhdr).h_dest = [0x47,0xae,0x8c,0x24,0x2f,0x10];
                        // (*ethhdr).h_dest = [0x74,0xea,0xc8,0x42,0xf2,0x01];
                        (*ethhdr).h_dest = [0x0, 0x0, 0x0, 0x0, 0x0, 0x01];

                        (*ip).saddr = lip;
                        (*ip).daddr = rip;

                        printk!("source: %d", lport);
                        (*tcp).source = lport;
                        (*tcp).dest = rport;

                        // l3 csum
                        printk!("original l3 csum: %x", (*ip).check);
                        (*ip).check = 0;
                        let mut csum = 0_u64;
                        csum_ipv4(ip, &mut csum);
                        printk!("new l3 csum: %lu -> %x", csum, csum as u16);
                        (*ip).check = csum as u16;

                        // l4 csum
                        printk!("original l4 csum: %x", (*tcp).check);

                        // v1
                        let data_start = tcp as *mut u32;
                        let data_len = size_of::<tcphdr>();
                        let mut csum = 0;
                        csum_ipv4_l4(data_start, data_len, &mut csum, ip);
                        printk!("new l4 csum: %lu -> %x", csum, csum as u16);

                        // v2
                        let mut csum = (*tcp).check as u64;
                        csum = csum_ipv4_l4_2(csum, (*ip).saddr, (*ip).daddr);
                        csum = csum_ipv4_l4_2(csum, vip, (*ip).daddr); // daddr
                        csum = csum_ipv4_l4_2(csum, saddr, lip); // saddr
                        csum = csum_ipv4_l4_2(csum, cport.into(), lport.into()); // sport
                        csum = csum_ipv4_l4_2(csum, vport.into(), 80_u32.to_be()); // dport
                        printk!("new l4 csum: %lu -> %x", csum, csum as u16);

                        // v4
                        let mut csum = (*tcp).check as u32;
                        csum = csum_ipv4_l4_4(csum, (*ip).saddr, (*ip).daddr);
                        csum = csum_ipv4_l4_4(csum, vip, (*ip).daddr); // daddr
                        csum = csum_ipv4_l4_4(csum, saddr, lip); // saddr
                        csum = csum_ipv4_l4_4(csum, cport.into(), lport.into()); // sport
                        csum = csum_ipv4_l4_4(csum, vport.into(), 80_u32.to_le()); // dport
                        printk!("new l4 csum: %u -> %x", csum, csum as u16);

                        // v5
                        let mut csum = (*tcp).check;
                        csum = csum_ipv4_l4_5_word(csum, saddr, lip); // saddr
                        csum = csum_ipv4_l4_5_word(csum, cdaddr, (*ip).daddr); // daddr
                        csum = csum_ipv4_l4_5(csum, cport, lport); // sport
                        csum = csum_ipv4_l4_5(csum, vport, rport); // dport
                        printk!("new l4 csum v5: %x", csum);

                        // v5 - protocol + all to le
                        let mut csum = (*tcp).check;
                        csum = csum_ipv4_l4_5_word(csum, saddr.to_le(), lip.to_le()); // saddr
                        csum = csum_ipv4_l4_5_word(csum, cdaddr.to_le(), (*ip).daddr.to_le()); // daddr
                        csum = csum_ipv4_l4_5_word(csum, (*ip).protocol.into(), 0x6); // protocol
                        csum = csum_ipv4_l4_5(csum, cport.to_le(), lport.to_le()); // sport
                        csum = csum_ipv4_l4_5(csum, vport.to_le(), rport.to_le()); // dport
                        printk!("new l4 csum v5-protocol + all le: %x", csum);

                        // let mut csum = (*tcp).check.to_le();
                        // csum = csum_ipv4_l4_5_word(csum, 0, lip); // saddr
                        // csum = csum_ipv4_l4_5_word(csum, 0, (*ip).daddr); // daddr
                        // csum = csum_ipv4_l4_5(csum, 0, u16::from((*ip).protocol)); // protocol
                        // csum = csum_ipv4_l4_5(csum, cport, lport); // sport
                        // csum = csum_ipv4_l4_5(csum, vport, rport); // dport
                        // csum = csum.to_be();
                        // printk!("new l4 csum: %x", csum);

                        let mut csum = csum_ipv4_l4_6((*tcp).check.to_le(), cip.to_le(), (*ip).saddr); // saddr
                        csum = csum_ipv4_l4_6(csum.to_le(), cdaddr.to_le(), rip); // daddr
                        csum = csum_ipv4_l4_6(csum.to_le(), u32::from(cport).to_le(), lport.into()); // sport
                        csum = csum_ipv4_l4_6(csum.to_le(), u32::from(vport).to_le(), rport.into()); // dport
                        // printk!("csum 32: %x 16: %x", csum, (csum.to_le() >> 16) as u16);
                        // let csum = ((csum.to_le() >> 16) as u16).to_be();
                        printk!("new l4 csum: %x", csum);

                        (*tcp).check = csum;

                        return Ok(XdpAction::Tx);
                    }

                    if t.dest() == lport {
                        bpf_trace_printk(b"hit local\0");
                        let mut localinfo = LocalInfo::new();
                        localinfo.ip = lip;
                        localinfo.port = lport;
                        let clientinfo = L2C.get(&localinfo).unwrap();
                        (*ip).saddr = vip;
                        (*ip).daddr = clientinfo.ip;

                        (*tcp).dest = clientinfo.port;
                        (*tcp).source = vport;
                        return Ok(XdpAction::Tx);
                    }

                    if (*ip).saddr == rip && (*tcp).dest != 32987 {
                        printk!("from rs: dport: %u", (*tcp).dest);
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
