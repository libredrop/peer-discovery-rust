//! UDP packet broadcasting utils.

use async_std::io;
use async_std::net::UdpSocket;
use futures_timer::Delay;
use std::time::Duration;
use std::net::Ipv4Addr;
use log::{info, error};
use futures::executor;
use futures::channel::mpsc;

use crate::error::Error;
use crate::proto::DiscoveryMsg;

const UDP_DISCOVERY_PORT: u16 = 5330;
const BEACON_EVERY_SECS: u64 = 3;

/// Beacons given discovery message on LAN using UDP broadcasting.
pub fn discover_peers(executor: &mut executor::ThreadPool, msg: DiscoveryMsg) -> Result<mpsc::UnboundedReceiver<DiscoveryMsg>, Error> {
    let our_peer_id = msg.id();
    let (tx, rx) = mpsc::unbounded();

    executor.spawn_ok(async move {
        if let Err(err) = listen_for_udp(our_peer_id, tx).await {
            error!("Listener socket failed: {:?}", err);
        }
    });

    executor.run(broadcast_discovery_msg(msg)).map_err(Error::Io)?;

    Ok(rx)
}

async fn broadcast_discovery_msg(msg: DiscoveryMsg) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    // TODO: ability to terminate the loop: cancel the future?
    let discovery_msg = msg.to_bytes();
    loop {
        socket.send_to(&discovery_msg, (Ipv4Addr::new(255, 255, 255, 255), UDP_DISCOVERY_PORT)).await?;
        Delay::new(Duration::from_secs(BEACON_EVERY_SECS)).await?;
    }
}

async fn listen_for_udp(my_id: [u8; 16], tx: mpsc::UnboundedSender<DiscoveryMsg>) -> io::Result<()> {
    let listen_addr = (Ipv4Addr::new(0, 0, 0, 0), UDP_DISCOVERY_PORT);
    let socket = UdpSocket::bind(listen_addr).await?;

    let mut buf = vec![0u8; 65535];
    loop {
        let (bytes_read, from_peer) = socket.recv_from(&mut buf).await?;
        let msg = match DiscoveryMsg::from_bytes(&buf[0..bytes_read]) {
            Ok(msg) => msg,
            Err(e) => {
                info!("Invalid discovery message received: {}, from: {}", e, from_peer);
                continue
            },
        };
        if msg.id() == my_id {
            continue;
        }
        if let Err(_) = tx.unbounded_send(msg) {
            break;
        }
    }
    Ok(())
}
