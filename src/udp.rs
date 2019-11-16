//! UDP packet broadcasting utils.

use async_std::io;
use async_std::net::UdpSocket;
use futures::channel::mpsc;
use futures::task::SpawnExt;
use futures::{executor, future, FutureExt, TryFutureExt};
use futures_timer::Delay;
use log::{error, info};
use std::net::Ipv4Addr;
use std::time::Duration;
use unwrap::unwrap;

use crate::error::Error;
use crate::proto::DiscoveryMsg;

const UDP_DISCOVERY_PORT: u16 = 5330;
const BEACON_EVERY_SECS: u64 = 3;

/// Beacons given discovery message on LAN using UDP broadcasting.
///
/// ## Returns
///
/// Async receiver that yields peer discovery messages. All the info about remote
/// peer is incoded in `DiscoveryMsg`.
pub fn discover_peers(
    executor: &mut executor::LocalPool,
    msg: DiscoveryMsg,
) -> Result<mpsc::UnboundedReceiver<DiscoveryMsg>, Error> {
    let our_peer_id = msg.id();
    let (tx, rx) = mpsc::unbounded();

    let listen =
        listen_for_udp(our_peer_id, tx).map_err(|e| error!("Listener socket failed: {}", e));
    let broadcast = broadcast_discovery_msg(msg)
        .map_err(|e| error!("Failed to broadcast discovery msgs: {}", e));
    unwrap!(executor
        .spawner()
        .spawn(future::try_join(listen, broadcast).map(|_| ())));

    Ok(rx)
}

async fn broadcast_discovery_msg(msg: DiscoveryMsg) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    // TODO: ability to terminate the loop: cancel the future?
    let discovery_msg = msg.to_bytes();
    loop {
        socket
            .send_to(
                &discovery_msg,
                (Ipv4Addr::new(255, 255, 255, 255), UDP_DISCOVERY_PORT),
            )
            .await?;
        Delay::new(Duration::from_secs(BEACON_EVERY_SECS)).await?;
    }
}

async fn listen_for_udp(
    my_id: [u8; 16],
    tx: mpsc::UnboundedSender<DiscoveryMsg>,
) -> io::Result<()> {
    let listen_addr = (Ipv4Addr::new(0, 0, 0, 0), UDP_DISCOVERY_PORT);
    let socket = UdpSocket::bind(listen_addr).await?;

    let mut buf = vec![0u8; 65535];
    loop {
        let (bytes_read, from_peer) = socket.recv_from(&mut buf).await?;
        let msg = match DiscoveryMsg::from_bytes(&buf[0..bytes_read]) {
            Ok(msg) => msg,
            Err(e) => {
                info!(
                    "Invalid discovery message received: {}, from: {}",
                    e, from_peer
                );
                continue;
            }
        };
        if msg.id() == my_id {
            continue;
        }
        if tx.unbounded_send(msg).is_err() {
            break;
        }
    }
    Ok(())
}
