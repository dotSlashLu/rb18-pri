use redbpf_probes::xdp::prelude::*;

const MAX_CONN: u32 = 16_776_960; // 256 * 65535
const MAX_SERVICE: u32 = 32; 

// link head
// 0: free
// 1: in use
#[map(link_section = "maps/link_heads")]
static mut LinkHeads: Array<u32> = Array::with_max_entries(2);

#[map(link_section = "maps/services")]
static mut Services: HashMap<Service, ServiceMeta> = HashMap::with_max_entries(MAX_SERVICE);

#[repr(C)]
#[derive(Debug)]
pub struct Service {
    vip: u32,
    port: u16,
    proto: u8,
}

#[repr(C)]
#[derive(Debug)]
pub struct ServiceMeta {
    
}

#[repr(C)]
#[derive(Debug)]
pub struct ClientConnMeta {
    service_idx: u32,
    local_conn_idx: u32, // client conn to local conntrack mapping
}

#[repr(C)]
#[derive(Debug)]
pub struct ClientConn {
    proto: u8,
    src: u32,
    port: u16,
}

// connection tracking table
#[map(link_section = "maps/contrack")]
static mut Conntrack: Array<ConntrackEntry> = Array::with_max_entries(MAX_CONN);

// client to conntrack mapping
#[map(link_section = "maps/clients")]
static mut Clients: HashMap<ClientConn, ClientConnMeta> = HashMap::with_max_entries(MAX_CONN);

/* 
    pub const BPF_TCP_ESTABLISHED: ::cty::c_uint = 1;
    pub const BPF_TCP_SYN_SENT: ::cty::c_uint = 2;
    pub const BPF_TCP_SYN_RECV: ::cty::c_uint = 3;
    pub const BPF_TCP_FIN_WAIT1: ::cty::c_uint = 4;
    pub const BPF_TCP_FIN_WAIT2: ::cty::c_uint = 5;
    pub const BPF_TCP_TIME_WAIT: ::cty::c_uint = 6;
    pub const BPF_TCP_CLOSE: ::cty::c_uint = 7;
    pub const BPF_TCP_CLOSE_WAIT: ::cty::c_uint = 8;
    pub const BPF_TCP_LAST_ACK: ::cty::c_uint = 9;
    pub const BPF_TCP_LISTEN: ::cty::c_uint = 10;
    pub const BPF_TCP_CLOSING: ::cty::c_uint = 11;
    pub const BPF_TCP_NEW_SYN_RECV: ::cty::c_uint = 12;
    pub const BPF_TCP_MAX_STATES: ::cty::c_uint = 13;
*/
#[repr(C)]
#[derive(PartialEq)]
enum ConnState {
    Free, // unused

    // tcp handshake
    Syn,    // timeout and syn-flood protection
    SynAck, // timeout and syn-flood protection

    Established,

    // tcp close
    Fin1, // fin sent, timeout
    FinAck1,
    Fin2, // ack recvd, timeout
    Tw,   // timeout

    // tcp other
    Rst, // reset

    Udp, // XXX: different protocol should be able to use the same port
}

#[repr(C)]
pub struct ConntrackEntry {
    ip_idx: u32,
    port: u16,
    state: ConnState,
    seq: u32,
    ts: u64, // time since system boot
    next: u32,
    client_conn: ClientConn, // local conntrack to client mapping
}

impl ConntrackEntry {
    fn syn(&mut self) {
        self.state = ConnState::Syn;
    }

    pub unsafe fn state(&mut self, pkt: Transport) {
        match pkt {
            Transport::TCP(tcph) => {
                // noop for possible retrans
                // XXX: how to deal with wrap around?
                if (*tcph).seq <= self.seq {
                    return;
                }

                let syn_set = (*tcph).syn() > 0;
                let ack_set = (*tcph).ack() > 0;

                if syn_set {
                    if ack_set {
                        self.state = ConnState::SynAck;
                    } else if self.state == ConnState::SynAck {
                        self.state = ConnState::Established;
                    } else if self.state == ConnState::Established {
                        // noop, possibly caused by retransmission
                    } else {
                        self.state = ConnState::Syn;
                    }
                    self.ts = bpf_ktime_get_boot_ns();
                    return;
                }

                if ack_set && self.state == ConnState::SynAck {
                    self.state = ConnState::Established;
                }

                let fin_set = (*tcph).fin() > 0;

                if fin_set || self.state == ConnState::Fin1 || self.state == ConnState::Fin2 {
                    if ack_set {
                        if self.state == ConnState::Fin1 {
                            self.state = ConnState::FinAck1;
                        } else if self.state == ConnState::Fin2 {
                            self.state = ConnState::Tw;
                        }
                        self.ts = bpf_ktime_get_boot_ns();
                        return;
                    }

                    if self.state == ConnState::Established {
                        self.state = ConnState::Fin1;
                    } else if self.state == ConnState::FinAck1 {
                        self.state = ConnState::Fin2;
                    }
                    self.ts = bpf_ktime_get_boot_ns();
                }

                if (*tcph).rst() > 0 {
                    // free it
                }
            }
            Transport::UDP(udph) => {}
        }
    }
}

