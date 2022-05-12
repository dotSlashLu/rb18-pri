pub mod csum;
pub mod csum_dpdk;

#[derive(Clone, Debug)]
#[repr(C)]
pub struct ClientInfo {
    pub ip: u32,
    pub port: u16,
    __pad: u16,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct LocalInfo {
    pub ip: u32,
    pub port: u16,
    __pad: u16,
}

impl ClientInfo {
    pub fn new() -> Self {
        Self {
            ip: 0,
            port: 0,
            __pad: 0,
        }
    }
}

impl LocalInfo {
    pub fn new() -> Self {
        Self {
            ip: 0,
            port: 0,
            __pad: 0,
        }
    }
}