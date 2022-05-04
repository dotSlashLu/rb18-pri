#![no_std]
#![no_main]
use redbpf_probes::maps::HashMap;
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut COUNTER: HashMap<u32, u32> = HashMap::with_max_entries(8);

#[xdp]
pub fn kern(ctx: XdpContext) -> XdpResult {
    let ip = match ctx.ip() {
        Ok(ip) => ip,
        Err(_) => return XdpResult::Ok(XdpAction::Pass),
    };

    let transport = unsafe {
        match ctx.transport() {
            Ok(t) => match (*ip).protocol as u32 {
                IPPROTO_TCP => {
                    // t::TCP
                    count(&IPPROTO_TCP);
                    return Ok(XdpAction::Pass);
                }
                IPPROTO_UDP => {
                    // t::UDP
                    count(&IPPROTO_UDP);
                    return Ok(XdpAction::Pass);
                }
                _ => return Ok(XdpAction::Pass),
            },
            Err(_) => return Ok(XdpAction::Pass),
        }
    };

    Ok(XdpAction::Pass)
}

fn count(proto: &u32) {
    let one = &1;
    unsafe {
        if let Some(v) = COUNTER.get(proto) {
            let n = v + 1;
            COUNTER.set(proto, &n);
        } else {
            COUNTER.set(proto, one)
        }
    }
}
