#![no_std]
#![no_main]
use core::mem;
use cty::*;
use memoffset::offset_of;

use probes::map_poc::Socket;

use redbpf_probes::maps::HashMap;
use redbpf_probes::socket_filter::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "map")]
static mut SocketMap: HashMap<Socket, i32> = HashMap::with_max_entries(8);

#[socket_filter]
fn entry(skb: SkBuff) -> SkBuffResult {
    let s1 = Socket { ip: 1, port: 1 };
    let zero = &0;
    // let s2 = Socket { ip: 2, port: 2 };
    unsafe {
        SocketMap.set(&s1, 0);
    }
    Ok(SkBuffAction::SendToUserspace)
}
