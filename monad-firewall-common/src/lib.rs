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

/// Host-side representation of an allowlist entry — no FFI layout constraints.
/// `AllowList` (below) is the eBPF map ABI; this is what callers actually reason about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowEntry {
    pub ip: u32,   // host byte order
    pub port: u16,
}

impl From<AllowEntry> for AllowList {
    fn from(entry: AllowEntry) -> Self {
        AllowList {
            ip: entry.ip,
            port: entry.port,
            _pad: 0,
        }
    }
}

impl From<AllowList> for AllowEntry {
    fn from(list: AllowList) -> Self {
        AllowEntry {
            ip: list.ip,
            port: list.port,
        }
    }
}
