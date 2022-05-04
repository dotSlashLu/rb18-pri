use ::core::fmt;
use ::core::mem::transmute;

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Socket {
    pub ip: u32,
    pub port: u16,
}

impl fmt::Display for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let octets: [u8; 4] = unsafe { transmute::<u32, [u8; 4]>(self.ip) };

        write!(
            f,
            "{:^3}.{:^3}.{:^3}.{:^3}:{:<5}",
            octets[3], octets[2], octets[1], octets[0], self.port
        )
    }
}