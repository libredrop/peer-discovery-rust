use std::collections::HashMap;
use std::net::Ipv4Addr;
use uuid::Uuid;

// Current protocol version.
const VERSION: u8 = 1;

#[repr(u8)]
pub enum TransportProtocol {
    Tcp = 0,
    Udp = 1,
}

/// Peer discovery message broadcasted via LAN so that others could find the service we are
/// exposing.
pub struct DiscoveryMsg {
    // Protocol version.
    version: u8,
    id: [u8; 16],
    service_name: String,
    protocol: TransportProtocol,
    service_port: u16,
    ipv4_addrs: Vec<Ipv4Addr>,
    items: HashMap<String, Vec<u8>>,
}

impl DiscoveryMsg {
    pub fn new(service_name: String, protocol: TransportProtocol, service_port: u16) -> Self {
        let id = Uuid::new_v4().as_bytes().clone();
        Self {
            version: VERSION,
            id,
            service_name,
            protocol,
            service_port,
            ipv4_addrs: vec![],
            items: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use speculate::speculate;

    speculate! {
        describe "Discovery Msg" {
            describe "new" {
                it "generates random peer ID" {
                    let msg = DiscoveryMsg::new("service1".to_string(), TransportProtocol::Tcp, 3000);

                    assert!(msg.id[0] > 0);
                }
            }
        }
    }
}
