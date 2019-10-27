//! A basic example that broadcasts service discovery messages and prints received ones from
//! remote peers.
//! You can use this example to test peer discovery on your LAN.

use peer_discovery::{discover_peers, DiscoveryMsg, TransportProtocol};
use unwrap::unwrap;
use simple_logger;
use log;
use futures::{StreamExt, future};

fn main() {
    unwrap!(simple_logger::init_with_level(log::Level::Info));
    let mut executor = unwrap!(futures::executor::ThreadPool::new());

    let msg = DiscoveryMsg::new("discovery-cli".into(), TransportProtocol::Tcp, 5000);
    let rx_msgs = unwrap!(discover_peers(&mut executor, msg));
    executor.run(rx_msgs.for_each(|msg| {
        println!("Received: {:?}", msg);
        future::ready(())
    }));
}
