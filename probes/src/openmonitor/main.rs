#![no_std]
#![no_main]
use core::mem;
use cty::*;
use memoffset::offset_of;

use probes::openmonitor::*;

// use one of the preludes
// use redbpf_probes::kprobe::prelude::*;
// use redbpf_probes::xdp::prelude::*;
use redbpf_probes::maps::HashMap;
use redbpf_probes::socket_filter::prelude::*;

// Use the types you're going to share with userspace, eg:
// use probes::openmonitor::SomeEvent;

program!(0xFFFFFFFE, "GPL");

// The maps and probe functions go here, eg:
//
// #[map]
// static mut syscall_events: PerfMap<SomeEvent> = PerfMap::with_max_entries(1024);
//
// #[kprobe("__x64_sys_open")]
// fn syscall_enter(regs: Registers) {
//   let pid_tgid = bpf_get_current_pid_tgid();
//   ...
//
//   let event = SomeEvent {
//     pid: pid_tgid >> 32,
//     ...
//   };
//   unsafe { syscall_events.insert(regs.ctx, &event) };
// }

#[map]
static mut COUNTER: HashMap<u32, u32> = HashMap::with_max_entries(4096);

#[socket_filter]
fn probe(skb: SkBuff) -> SkBuffResult {

    let eth_len = mem::size_of::<ethhdr>();
    let eth_proto = skb.load::<__be16>(offset_of!(ethhdr, h_proto))? as u32;
    if eth_proto != ETH_P_IP {
        return Ok(SkBuffAction::SendToUserspace);
    }
    let ip_proto = skb.load::<__u8>(eth_len + offset_of!(iphdr, protocol))? as u32;

    let one: &u32 = &0;
    unsafe {
        match COUNTER.get(&ip_proto) {
            Some(v) => {
                let n = v + 1;
                COUNTER.set(&ip_proto, &n)
            }
            None => COUNTER.set(&ip_proto, one),
        };
    }

    if ip_proto == IPPROTO_ICMP {
        return Ok(SkBuffAction::Ignore)
    }

    Ok(SkBuffAction::SendToUserspace)
}
