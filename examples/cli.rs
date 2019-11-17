//! A basic example that broadcasts service discovery messages and prints received ones from
//! remote peers.
//! You can use this example to test peer discovery on your LAN.

use async_std::task;
use futures::{future, StreamExt};
use log;
use peer_discovery::{discover_peers, DiscoveryMsg, TransportProtocol};
use simple_logger;
use unwrap::unwrap;

fn main() {
    unwrap!(simple_logger::init_with_level(log::Level::Info));

    let msg = DiscoveryMsg::new("discovery-cli".into(), TransportProtocol::Tcp, 5000);
    let rx_msgs = unwrap!(discover_peers(msg));
    task::block_on(rx_msgs.for_each(|msg| {
        println!("Received: {:?}", msg);
        future::ready(())
    }));
}
