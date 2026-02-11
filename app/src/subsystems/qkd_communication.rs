use std::collections::HashMap;
use std::net::SocketAddr;

use bitvec::vec::BitVec;
use core::sync::tasks::Monitor;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, info, instrument};

use core::key_state_machine::{Key, Sifted};

use crate::errors::{MainResult, SubsystemError, SubsystemResult};
use crate::models::update_qkd::RequestQkdKeys;
use crate::models::{DeviceId, KeyId};
use crate::models::{LocalDeviceId, PeerId};

async fn get_key(connection: &quinn::Connection) -> MainResult<(KeyId, DeviceId, BitVec)> {
    let mut stream = connection.accept_uni().await?;
    let data = stream.read_to_end(1024 * 1024).await?;
    Ok(bincode::deserialize(&data)?)
}

fn create_key_from_data(data: BitVec, key_id: KeyId, device_id: DeviceId) -> Key<Sifted> {
    Key::new(data, key_id.into(), device_id.into(), 0)
}

#[instrument(level="ERROR", skip_all, fields(%addr=connection.remote_address()))]
async fn handle_qkd(
    monitor: Monitor,
    connection: quinn::Connection,
    new_key: Sender<Key<Sifted>>,
) -> MainResult<()> {
    info!("Handling qkd keys");
    loop {
        tokio::select! {
            _ = monitor.cancelled() => return Ok(()),
            err = connection.closed() => {
                info!("Connection with QKD closed: {}", err);
                return Ok(())
            },
            Ok((key_id, device_id, keydata)) = get_key(&connection) => {
                info!("Received a key from {}: {} bits | key id: {}", device_id, keydata.len(), key_id);
                let key = create_key_from_data(keydata, key_id, device_id);
                new_key.send(key).await?
            }
        }
    }
}

#[instrument(level = "ERROR", skip_all)]
pub async fn qkd_manager(
    monitor: Monitor,
    addr: SocketAddr,
    config: quinn::ServerConfig,
    peers: HashMap<PeerId, Vec<LocalDeviceId>>,
    mut peer_connected: Receiver<RequestQkdKeys>,
) -> SubsystemResult {
    let listener = quinn::Endpoint::server(config, addr)?;
    info!("Listening for qkd connections on {}", addr);
    let (key_sender, mut key_receiver) = tokio::sync::mpsc::channel(1024);
    let mut channels = HashMap::<LocalDeviceId, Sender<Key<Sifted>>>::new();
    loop {
        tokio::select! {
            _ = monitor.cancelled() => return Ok(()),
            Some(conn) = listener.accept() => {
                info!("Incoming QKD connection");
                let connection = conn.await.map_err(|e| SubsystemError(format!("Unable to open a connection: {}", e)))?;
                monitor.run(handle_qkd(monitor.clone(), connection, key_sender.clone()));
            },
            Some(key) = key_receiver.recv() => {
                match channels.get(&key.device_id().into()) {
                    Some(tx) => {
                        if tx.send(key).await.is_err() {
                            error!("Unable to send key for further processing!");
                        }
                    },
                    None => info!("Peer of device not yet connected"),
                }
            }
            Some(request) = peer_connected.recv() => {
                let (tx, rx) = tokio::sync::mpsc::channel::<Key<Sifted>>(64);
                let response = peers.get(request.peer_id())
                    .and_then(|devices| {
                        devices.contains(request.device_id())
                            .then(|| {
                                channels.insert(*request.device_id(), tx);
                                rx
                            })});
                if request.reply(response).is_err() {
                    error!("Unable to request QKD key");
                }
            }
        }
    }
}
