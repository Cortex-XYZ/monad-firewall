#![no_std]

/// request bits
/// ctx.data()                                                      ctx.data_end()
///     │                                                                   │
///     ▼                                                                   ▼
/// ┌──────────────┬──────────────┬───────────────┬──────────────────────┐
/// │ Ethernet Hdr │ IPv4 Hdr     │ TCP/UDP Hdr   │ Payload              │
/// │ 14 bytes     │ 20 bytes     │ 8 (UDP) /     │                      │
/// │              │              │ 20+ (TCP)     │                      │
/// └──────────────┴──────────────┴───────────────┴──────────────────────┘
///  offset 0       offset 14      offset 34
#[repr(C)]
pub struct AllowList {
    pub ip: u32,
    pub port: u16,
    pub _pad: u16, // align to 8 bytes
}
