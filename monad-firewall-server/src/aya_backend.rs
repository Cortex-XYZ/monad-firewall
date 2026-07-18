use std::net::Ipv4Addr;
use std::path::Path;

use aya::maps::{HashMap as AyaHashMap, Map, MapData};

use crate::{FirewallError, FirewallState, Rule, SourceCounter};


fn key_to_ip(key: u32) -> Ipv4Addr {
    Ipv4Addr::from(key)
}

pub struct AyaFirewallState {
    counters: AyaHashMap<MapData, u32, u64>,
}

impl AyaFirewallState {
    pub fn from_pin(counters_pin: impl AsRef<Path>) -> anyhow::Result<Self> {
        let map_data = MapData::from_pin(counters_pin)?;
        let counters = AyaHashMap::try_from(Map::HashMap(map_data))?;
        Ok(Self { counters })
    }
}

impl FirewallState for AyaFirewallState {
    fn list_rules(&self) -> Result<Vec<Rule>, FirewallError> {
        // TODO(monad-firewall#rules): read the allowlist map (keyed by the shared AllowList type).
        Err(FirewallError::Unsupported("reading the allowlist map"))
    }

    fn add_rule(&self, _rule: Rule) -> Result<(), FirewallError> {
        Err(FirewallError::Unsupported(
            "writing rules via the eBPF backend",
        ))
    }

    fn remove_rule(&self, _rule: &Rule) -> Result<(), FirewallError> {
        Err(FirewallError::Unsupported(
            "writing rules via the eBPF backend",
        ))
    }

    fn counters(&self) -> Result<Vec<SourceCounter>, FirewallError> {
        self.counters
            .iter()
            .map(|entry| {
                let (key, packets) = entry.map_err(FirewallError::Map)?;
                Ok(SourceCounter {
                    ip: key_to_ip(key),
                    packets,
                    dropped: 0,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::key_to_ip;
    use std::net::Ipv4Addr;

    #[test]
    fn key_is_decoded_as_network_order() {
        // 0x7F000001 == 127.0.0.1 when read big-endian.
        assert_eq!(key_to_ip(0x7f00_0001), Ipv4Addr::LOCALHOST);
    }
}
