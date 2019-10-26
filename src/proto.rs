//! Peer discovery message related facilities: serialization/deserialization to/from binary data
//! on a wire, etc.

use std::net::Ipv4Addr;
use uuid::Uuid;
use crate::error::{Error, DeserializeError};


// Current protocol version.
pub const VERSION: u8 = 1;


#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum TransportProtocol {
    Tcp = 0,
    Udp = 1,
}

/// Peer discovery message broadcasted via LAN so that others could find the service we are
/// exposing.
#[derive(Debug)]
pub struct DiscoveryMsg {
    // Protocol version.
    version: u8,
    // Randomly generated peer ID.
    id: [u8; 16],
    service_name: String,
    protocol: TransportProtocol,
    service_port: u16,
    ipv4_addrs: Vec<Ipv4Addr>,
    items: Vec<(String, Vec<u8>)>,
}

impl DiscoveryMsg {
    /// Constructs new discovery message with no IP addresses nor data items.
    /// Random peer ID is generated.
    pub fn new(service_name: String, protocol: TransportProtocol, service_port: u16) -> Self {
        // TODO: use some value bounds checking attributes.
        assert!(service_name.len() < 256, "Service name max length is 255 bytes.");

        let id = Uuid::new_v4().as_bytes().clone();
        Self {
            version: VERSION,
            id,
            service_name,
            protocol,
            service_port,
            ipv4_addrs: vec![],
            items: vec![],
        }
    }

    /// Deserializes a byte buffer (UDP packet) into `DiscoveryMsg`.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        let version = buf[0];

        // Parsing position.
        let mut pos = 1;
        let id = parse_id(buf, &mut pos)?;
        let service_name_len = parse_service_name_len(buf, &mut pos)?;
        let service_name = parse_service_name(buf, &mut pos, service_name_len)?;
        let protocol = parse_protocol(buf, &mut pos)?;
        let service_port = parse_service_port(buf, &mut pos)?;
        let ipv4_addrs = parse_ipv4_addrs(buf, &mut pos)?;
        let items_count = parse_items_count(buf, &mut pos)?;
        let keys = parse_items_keys(buf, &mut pos, items_count)?;
        let values = parse_items_values(buf, &mut pos, items_count)?;
        let items: Vec<_> = keys.into_iter().zip(values.into_iter()).collect();

        Ok(Self {
            version,
            id,
            service_name,
            protocol,
            service_port,
            ipv4_addrs,
            items,
        })
    }

    /// `DiscoveryMsg` advertises the addresses peer is exposing its services on.
    /// This method allows to add new IP address to the list.
    ///
    /// ## Returns
    /// `false` if the maximum number of addresses (255) is reached.
    pub fn add_addrv4(&mut self, addr: Ipv4Addr) -> bool {
        if self.ipv4_addrs.len() < 255 {
            self.ipv4_addrs.push(addr);
            true
        } else {
            false
        }
    }

    /// Add arbitrary data to the discovery message.
    pub fn add_data(&mut self, key: String, value: Vec<u8>) -> Result<(), Error> {
        if key.len() > 255 {
            return Err(Error::TooLongKey);
        }
        if self.items.len() == 255 {
            return Err(Error::TooManyDataItems);
        }
        self.items.push((key, value));
        Ok(())
    }

    /// Serializes discovery message to `peer-discovery` binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.id.len() + 1 + self.service_name.len() + 2);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.id);
        bytes.push(self.service_name.len() as u8);
        bytes.extend_from_slice(self.service_name.as_bytes());
        bytes.push(self.protocol as u8);
        bytes.extend_from_slice(&self.service_port.to_be_bytes());

        bytes.push(self.ipv4_addrs.len() as u8);
        for addr in &self.ipv4_addrs {
            bytes.extend_from_slice(&addr.octets());
        }

        bytes.push(self.items.len() as u8);
        for (key, _) in &self.items {
            bytes.push(key.len() as u8);
        }
        for (key, _) in &self.items {
            bytes.extend_from_slice(key.as_bytes());
        }

        for (_, value) in &self.items {
            bytes.push(value.len() as u8);
        }
        for (_, value) in &self.items {
            bytes.extend_from_slice(value);
        }

        bytes
    }
}

fn parse_id(buf: &[u8], pos: &mut usize) -> Result<[u8; 16], DeserializeError> {
    if buf.len() - *pos < 16 {
        return Err(DeserializeError::NotEnoughBytes("id".into(), 16, buf.len() - *pos, *pos));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&buf[*pos..*pos + 16]);
    *pos += 16;
    Ok(id)
}

fn parse_service_name_len(buf: &[u8], pos: &mut usize) -> Result<usize, DeserializeError> {
    if buf.len() - *pos < 1 {
        return Err(DeserializeError::NotEnoughBytes("service_name_len".into(), 1, buf.len() - *pos, *pos));
    }
    let service_name_len = usize::from(buf[*pos]);
    *pos += 1;
    Ok(service_name_len)
}

fn parse_service_name(buf: &[u8], pos: &mut usize, service_name_len: usize) -> Result<String, DeserializeError> {
    if *pos + service_name_len > buf.len() {
        return Err(DeserializeError::NotEnoughBytes(
            "service_name".into(), service_name_len, buf.len() - *pos, *pos));
    }

    let service_name = match String::from_utf8(buf[*pos..*pos + service_name_len].to_vec()) {
        Ok(service_name) => service_name,
        Err(e) => return Err(DeserializeError::InvalidUtf8("service_name".into(), e.utf8_error())),
    };
    *pos += service_name_len;

    Ok(service_name)
}

fn parse_protocol(buf: &[u8], pos: &mut usize) -> Result<TransportProtocol, DeserializeError> {
    if *pos + 1 > buf.len() {
        return Err(DeserializeError::NotEnoughBytes(
            "protocol".into(), 1, buf.len() - *pos, *pos));
    }
    let protocol = match buf[*pos] {
        0 => TransportProtocol::Tcp,
        1 => TransportProtocol::Udp,
        proto => return Err(DeserializeError::UnknownProtocol(proto)),
    };
    *pos += 1;
    Ok(protocol)
}

fn parse_service_port(buf: &[u8], pos: &mut usize) -> Result<u16, DeserializeError> {
    if *pos + 2 > buf.len() {
        return Err(DeserializeError::NotEnoughBytes(
            "service_port".into(), 2, buf.len() - *pos, *pos));
    }
    let service_port = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
    *pos += 2;
    Ok(service_port)
}

fn parse_ipv4_addrs(buf: &[u8], pos: &mut usize) -> Result<Vec<Ipv4Addr>, DeserializeError> {
    if *pos + 1 > buf.len() {
        return Err(DeserializeError::NotEnoughBytes(
            "ipv4_addrs_count".into(), 1, buf.len() - *pos, *pos));
    }
    let ipv4_addrs_count = usize::from(buf[*pos]);
    *pos += 1;

    let mut ipv4_addrs = Vec::with_capacity(ipv4_addrs_count);
    for _ in 0..ipv4_addrs_count {
        if *pos + 4 > buf.len() {
            return Err(DeserializeError::NotEnoughBytes(
                "ipv4_addr".into(), 4, buf.len() - *pos, *pos));
        }
        let ip = Ipv4Addr::new(buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]);
        ipv4_addrs.push(ip);
        *pos += 4;
    }
    Ok(ipv4_addrs)
}

fn parse_items_count(buf: &[u8], pos: &mut usize) -> Result<usize, DeserializeError> {
    if *pos + 1 > buf.len() {
        return Err(DeserializeError::NotEnoughBytes(
            "items_count".into(), 1, buf.len() - *pos, *pos));
    }
    let items_count = usize::from(buf[*pos]);
    *pos += 1;
    Ok(items_count)
}

fn parse_items_keys(
        buf: &[u8], pos: &mut usize, items_count: usize) -> Result<Vec<String>, DeserializeError> {
    if *pos + items_count > buf.len() {
        return Err(DeserializeError::NotEnoughBytes(
            "keys_len".into(), items_count, buf.len() - *pos, *pos));
    }
    let keys_len = &buf[*pos..*pos + items_count];
    *pos += items_count;

    let mut keys = Vec::with_capacity(items_count);
    for i in 0..items_count {
        let key_len = usize::from(keys_len[i]);
        if *pos + key_len > buf.len() {
            return Err(DeserializeError::NotEnoughBytes(
                "item key".into(), 1, buf.len() - *pos, *pos));
        }
        let key = match String::from_utf8(buf[*pos..*pos + key_len].to_vec()) {
            Ok(key) => key,
            Err(e) => return Err(DeserializeError::InvalidUtf8("item key".into(), e.utf8_error())),
        };
        keys.push(key);

        *pos += key_len;
    }
    Ok(keys)
}

fn parse_items_values(
        buf: &[u8], pos: &mut usize, items_count: usize) -> Result<Vec<Vec<u8>>, DeserializeError> {
    if *pos + items_count > buf.len() {
        return Err(DeserializeError::NotEnoughBytes(
            "items_len".into(), items_count, buf.len() - *pos, *pos));
    }
    let values_len = &buf[*pos..*pos + items_count];
    *pos += items_count;

    let mut values = Vec::with_capacity(items_count);
    for i in 0..items_count {
        let value_len = usize::from(values_len[i]);
        if *pos + value_len > buf.len() {
            return Err(DeserializeError::NotEnoughBytes(
                "item value".into(), 1, buf.len() - *pos, *pos));
        }
        values.push(buf[*pos..*pos + value_len].to_vec());
        *pos += value_len;
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use speculate::speculate;
    use proptest::prelude::*;

    macro_rules! expect_err {
        ($res:expr, $e:pat) => {
            if let Err($e) = $res {
                ()
            } else {
                panic!("Expected {}, got {:?}", stringify!($e), $res);
            }
        }
    }

    speculate! {
        describe "Discovery Msg" {
            describe "new" {
                it "generates random peer ID" {
                    let msg = DiscoveryMsg::new("service1".to_string(), TransportProtocol::Tcp, 3000);

                    assert!(msg.id[0] > 0);
                }
            }

            describe "add_addvr4" {
                it "returns true when address is appended to the list" {
                    let mut msg = DiscoveryMsg::new("service1".to_string(), TransportProtocol::Tcp, 3000);

                    let added = msg.add_addrv4(Ipv4Addr::new(1, 2, 3, 4));

                    assert!(added);
                }

                it "returns false when message already has 255 addresses" {
                    let mut msg = DiscoveryMsg::new("service1".to_string(), TransportProtocol::Tcp, 3000);
                    for i in 1..=255 {
                        msg.add_addrv4(Ipv4Addr::new(1, 2, 3, i));
                    }

                    let added = msg.add_addrv4(Ipv4Addr::new(1, 2, 3, 4));

                    assert!(!added);
                }
            }

            describe "add_data" {
                it "returns error when data key is longer than 255 bytes" {
                    let mut msg = DiscoveryMsg::new("service1".to_string(), TransportProtocol::Tcp, 3000);

                    let key = String::from_utf8([b'a'; 300].to_vec()).unwrap();
                    let res = msg.add_data(key, vec![1, 2, 3]);

                    assert!(res.is_err());
                }

                it "returns error when message already has 255 data items" {
                    let mut msg = DiscoveryMsg::new("service1".to_string(), TransportProtocol::Tcp, 3000);
                    for i in 1..=255 {
                        let _ = msg.add_data(i.to_string(), vec![1, 2, 3]);
                    }

                    let res = msg.add_data("new_key".to_string(), vec![1, 2, 3]);

                    assert!(res.is_err());
                }
            }

            describe "to_bytes" {
                it "puts version as first byte" {
                    let msg = DiscoveryMsg::new("service1".to_string(), TransportProtocol::Tcp, 3000);

                    let bytes = msg.to_bytes();

                    assert!(bytes[0] == VERSION);
                }

                it "writes 16 byte peer ID" {
                    let msg = DiscoveryMsg::new("service1".to_string(), TransportProtocol::Tcp, 3000);

                    let bytes = msg.to_bytes();

                    assert!(bytes[1..17] == msg.id);
                }

                proptest! {
                    #[test]
                    fn it_writes_service_name_string_length(ref service_name in ".{64}") {
                        let msg = DiscoveryMsg::new(service_name.to_string(), TransportProtocol::Tcp, 3000);

                        let bytes = msg.to_bytes();

                        assert!(bytes[17] as usize == service_name.len());
                    }

                    #[test]
                    fn it_writes_service_name_content(ref service_name in ".{64}") {
                        let msg = DiscoveryMsg::new(service_name.to_string(), TransportProtocol::Tcp, 3000);

                        let bytes = msg.to_bytes();

                        let serialized_name = String::from_utf8(
                            bytes[18..18 + service_name.len()].to_vec()).unwrap();
                        assert!(serialized_name == *service_name);
                    }

                    #[test]
                    fn it_serializes_port_in_big_endian(port in 1..65535u16) {
                        let msg = DiscoveryMsg::new("s".to_string(), TransportProtocol::Tcp, port);

                        let bytes = msg.to_bytes();

                        let serialized_port = ((bytes[20] as u16) << 8) | (bytes[21] as u16);
                        assert!(serialized_port == port);
                    }
                }

                it "writes TCP protocol number" {
                    let msg = DiscoveryMsg::new("s".to_string(), TransportProtocol::Tcp, 5000);

                    let bytes = msg.to_bytes();

                    assert!(bytes[19] == 0);
                }

                it "writes UDP protocol number" {
                    let msg = DiscoveryMsg::new("s".to_string(), TransportProtocol::Udp, 5000);

                    let bytes = msg.to_bytes();

                    assert!(bytes[19] == 1);
                }

                it "writes the number of IP address" {
                    let mut msg = DiscoveryMsg::new("s".to_string(), TransportProtocol::Tcp, 3000);
                    msg.add_addrv4(Ipv4Addr::new(1, 2, 3, 4));
                    msg.add_addrv4(Ipv4Addr::new(1, 2, 3, 5));
                    msg.add_addrv4(Ipv4Addr::new(1, 2, 3, 6));

                    let bytes = msg.to_bytes();

                    assert!(bytes[22] == 3);
                }

                it "writes all IP address" {
                    let mut msg = DiscoveryMsg::new("s".to_string(), TransportProtocol::Tcp, 3000);
                    msg.add_addrv4(Ipv4Addr::new(1, 2, 3, 4));
                    msg.add_addrv4(Ipv4Addr::new(1, 2, 3, 5));

                    let bytes = msg.to_bytes();

                    assert!(bytes[23..27] == [1, 2, 3, 4]);
                }

                it "writes the number of key-value items" {
                    let mut msg = DiscoveryMsg::new("s".to_string(), TransportProtocol::Tcp, 3000);
                    let _ = msg.add_data("key1".into(), vec![1, 2, 3]);
                    let _ = msg.add_data("key2".into(), vec![2, 3, 4]);
                    let _ = msg.add_data("key3".into(), vec![3, 4, 5]);

                    let bytes = msg.to_bytes();

                    assert!(bytes[23] == 3);
                }

                it "writes lengths for all keys of data items" {
                    let mut msg = DiscoveryMsg::new("s".to_string(), TransportProtocol::Tcp, 3000);
                    let _ = msg.add_data("key1".into(), vec![1, 2, 3]);
                    let _ = msg.add_data("key_2".into(), vec![2, 3, 4]);

                    let bytes = msg.to_bytes();

                    assert!(bytes[24] == 4);
                    assert!(bytes[25] == 5);
                }

                it "writes all keys of data items" {
                    let mut msg = DiscoveryMsg::new("s".to_string(), TransportProtocol::Tcp, 3000);
                    let _ = msg.add_data("key1".into(), vec![1, 2, 3]);
                    let _ = msg.add_data("key_2".into(), vec![2, 3, 4]);

                    let bytes = msg.to_bytes();

                    assert!(bytes[26..30] == *"key1".as_bytes());
                    assert!(bytes[30..35] == *"key_2".as_bytes());
                }

                it "writes lengths of all data items" {
                    let mut msg = DiscoveryMsg::new("s".to_string(), TransportProtocol::Tcp, 3000);
                    let _ = msg.add_data("key1".into(), vec![1, 2]);
                    let _ = msg.add_data("key_2".into(), vec![2, 3, 4]);

                    let bytes = msg.to_bytes();

                    assert!(bytes[35] == 2);
                    assert!(bytes[36] == 3);
                }

                it "writes all values of data items" {
                    let mut msg = DiscoveryMsg::new("s".to_string(), TransportProtocol::Tcp, 3000);
                    let _ = msg.add_data("key1".into(), vec![1, 2]);
                    let _ = msg.add_data("key_2".into(), vec![2, 3, 4]);

                    let bytes = msg.to_bytes();

                    assert!(bytes[37..39] == [1, 2]);
                    assert!(bytes[39..42] == [2, 3, 4]);
                }
            }

            describe "from_bytes" {
                it "deserializes completely the same message as was serialized" {
                    let mut msg = DiscoveryMsg::new("service1".to_string(), TransportProtocol::Udp, 5000);
                    let _ = msg.add_data("key1".into(), vec![1, 2, 3]);
                    let _ = msg.add_data("key2".into(), vec![2, 3, 4]);
                    let _ = msg.add_addrv4(Ipv4Addr::new(1, 2, 3, 4));
                    let _ = msg.add_addrv4(Ipv4Addr::new(2, 3, 4, 5));
                    let msg_buf = msg.to_bytes();

                    let msg2 = DiscoveryMsg::from_bytes(&msg_buf[..]).unwrap();

                    assert!(msg2.version == msg.version);
                    assert!(msg2.id == msg.id);
                    assert!(msg2.service_name == msg.service_name);
                    assert!(msg2.protocol == msg.protocol);
                    assert!(msg2.service_port == msg.service_port);
                    assert!(msg2.ipv4_addrs == msg.ipv4_addrs);
                    assert!(msg2.items == msg.items);
                }

                it "returns error when there is not enough bytes for ID" {
                    let res = DiscoveryMsg::from_bytes(&[1, 2, 3]);

                    expect_err!(res, Error::Deserialize(DeserializeError::NotEnoughBytes(..)));
                }

                it "returns error when there is not enough bytes for service name length" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16]);

                    expect_err!(res, Error::Deserialize(DeserializeError::NotEnoughBytes(..)));
                }

                it "returns error when there is less bytes than service name length says" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', b'b']);

                    expect_err!(res, Error::Deserialize(DeserializeError::NotEnoughBytes(..)));
                }

                it "returns error when service name is not valid UTF-8" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', 0b11000000, 0]);

                    expect_err!(res, Error::Deserialize(DeserializeError::InvalidUtf8(..)));
                }

                it "returns error when not enough bytes for protocol number" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', b'b', b'c']);

                    expect_err!(res, Error::Deserialize(DeserializeError::NotEnoughBytes(..)));
                }

                it "returns error when protocol number is unknown" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', b'b', b'c', 127]);

                    expect_err!(res, Error::Deserialize(DeserializeError::UnknownProtocol(127)));
                }

                it "returns error when not enough bytes for service port" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', b'b', b'c', 1, 80]);

                    expect_err!(res, Error::Deserialize(DeserializeError::NotEnoughBytes(..)));
                }

                it "returns error when not enough bytes for IPv4 addresses count" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', b'b', b'c', 1, 80, 0]);

                    expect_err!(res, Error::Deserialize(DeserializeError::NotEnoughBytes(..)));
                }

                it "returns error when not enough bytes for IPv4 address" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', b'b', b'c', 1, 80, 0, 2, 1, 2, 3, 4,
                        1, 2, 3]);

                    expect_err!(res, Error::Deserialize(DeserializeError::NotEnoughBytes(..)));
                }

                it "returns error when not enough bytes for items count" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', b'b', b'c', 1, 80, 0, 1, 1, 2, 3, 4,
                    ]);

                    expect_err!(res, Error::Deserialize(DeserializeError::NotEnoughBytes(..)));
                }

                it "returns error when not enough bytes for items keys length" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', b'b', b'c', 1, 80, 0, 1, 1, 2, 3, 4,
                        2, 3]);

                    expect_err!(res, Error::Deserialize(DeserializeError::NotEnoughBytes(..)));
                }

                it "returns error when not enough bytes for some item key" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', b'b', b'c', 1, 80, 0, 1, 1, 2, 3, 4,
                        1, 3, b'a', b'b']);

                    expect_err!(res, Error::Deserialize(DeserializeError::NotEnoughBytes(..)));
                }

                it "returns error when item key is not valid UTF-8" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', b'b', b'c', 1, 80, 0, 1, 1, 2, 3, 4,
                        1, 3, b'a', 0b11000000, 0]);

                    expect_err!(res, Error::Deserialize(DeserializeError::InvalidUtf8(..)));
                }

                it "returns error when not enough bytes for items values length" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', b'b', b'c', 1, 80, 0, 1, 1, 2, 3, 4,
                        2, 1, 1, b'a', b'b', 1]);

                    expect_err!(res, Error::Deserialize(DeserializeError::NotEnoughBytes(..)));
                }

                it "returns error when not enough bytes for items value vector" {
                    let res = DiscoveryMsg::from_bytes(&[1, 1, 2, 3, 4, 5, 6, 7, 8,
                        9, 10, 11, 12, 13, 14, 15, 16, 3, b'a', b'b', b'c', 1, 80, 0, 1, 1, 2, 3, 4,
                        2, 1, 1, b'a', b'b', 1, 2, 0, 0]);

                    expect_err!(res, Error::Deserialize(DeserializeError::NotEnoughBytes(..)));
                }
            }
        }
    }
}
