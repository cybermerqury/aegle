use std::fmt::Debug;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, info, instrument, warn};

use crate::communication::parse::{read_message, send_message};
use crate::communication::quic::QuinnStream;
use crate::errors::{ErrorMessage, MainResult, SubsystemError, SubsystemResult};
use crate::models::update_qkd::RequestQkdKeys;
use crate::models::{LocalDeviceId, OwnID, PeerId, PeerManagementArgs, PeerStates, Peers};

use core::sync::tasks::Monitor;

use super::{role, RemoteToLocal};

#[instrument(level = "ERROR", skip_all)]
pub async fn try_connect_to_peer(
    full_id: &(OwnID, LocalDeviceId),
    addr: SocketAddr,
    config: quinn::ClientConfig,
) -> MainResult<QuinnStream> {
    let src_socket = SocketAddr::from_str("0.0.0.0:0")?;
    let endpoint = quinn::Endpoint::client(src_socket)?;
    let connection = endpoint.connect_with(config, addr, "localhost")?.await?;
    let mut stream = QuinnStream::connect(connection).await?;
    send_message(&mut stream, &full_id).await?;
    let mut buff = vec![0; 512];
    match read_message(&mut stream, &mut buff).await? {
        ConnectionStatus::Accepted => {
            info!("Connection established");
            Ok(stream)
        }
        ConnectionStatus::UnknownPeer => {
            warn!("Unknown peer");
            Err(ErrorMessage("Unknown peer").into())
        }
        ConnectionStatus::AlreadyConnected => {
            info!("Connected already, rejected");
            Err(ErrorMessage("Already connected").into())
        }
    }
}

#[derive(Debug)]
pub enum Side {
    Server,
    Client,
}

#[instrument(level="info", skip_all, fields(%peer=peer_id, %device=device_id, ?side=side))]
async fn launch_peer_communication(
    monitor: Monitor,
    peer_id: PeerId,
    device_id: LocalDeviceId,
    mut stream: QuinnStream,
    side: Side,
    connection_update: Sender<PeerUpdate>,
    request_qkd: Sender<RequestQkdKeys>,
) -> MainResult<()> {
    info!(
        "Launching peer communication as {:?} with peer {}",
        side, peer_id
    );
    let mut recv_buff = vec![0; 1024];
    let connection = stream.get_connection();
    let role = match side {
        Side::Server => handshake_server(&mut stream, &mut recv_buff).await?,
        Side::Client => handshake_client(&mut stream, &mut recv_buff).await?,
    };
    let (request, reply) = RequestQkdKeys::new(peer_id, device_id);
    if (request_qkd.send(request).await).is_err() {
        error!("Qkd subsystem is down!");
        return Err(ErrorMessage("Cannot get keys for peer").into());
    }
    let Some(new_keys) = reply.await? else {
        error!("No qkd device {}", device_id);
        return Err(ErrorMessage("Device not recognised").into());
    };
    match role {
        Role::Leader => {
            monitor.run(role::leader::start_leader(
                monitor.clone(),
                connection.clone(),
                peer_id,
                device_id,
                new_keys,
            ));
        }
        Role::Follower => {
            monitor.run(role::follower::start_follower(
                monitor.clone(),
                connection.clone(),
                peer_id,
                device_id,
                new_keys,
            ));
        }
    }
    stream.shutdown_streams()?;
    tokio::select! {
        reason = connection.closed() => {
            connection_update.send(PeerUpdate::Disconnection(peer_id, device_id, reason)).await?;
        },
        _ = monitor.cancelled() => {},
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
enum Ping {
    Ping,
    Pong,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
enum Role {
    Leader,
    Follower,
}

impl Role {
    fn opposite(&self) -> Self {
        match self {
            Self::Leader => Self::Follower,
            Self::Follower => Self::Leader,
        }
    }
}

type KnownEC = Vec<String>;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
enum HandshakeMessages {
    KnownAlgos(KnownEC),
    Acknowledge(Role),
}

pub enum PeerUpdate {
    NewConnection(QuinnStream, PeerId, LocalDeviceId, Side),
    Disconnection(PeerId, LocalDeviceId, quinn::ConnectionError),
}

impl Debug for PeerUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewConnection(_, peer_id, device_id, _) => {
                writeln!(
                    f,
                    "NewConnection(peer_id={}, device_id={})",
                    peer_id, device_id
                )
            }
            Self::Disconnection(peer_id, device_id, _) => {
                writeln!(
                    f,
                    "Disconnected(peer_id={}, device_id={})",
                    peer_id, device_id
                )
            }
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum ConnectionStatus {
    Accepted,
    AlreadyConnected,
    UnknownPeer,
}

#[instrument(level="error", skip_all, fields(%peer_uuid=peer_uuid, %device_id=device_id, %addr=addr))]
async fn connect_to_peer(
    uuid: OwnID,
    peer_uuid: PeerId,
    device_id: LocalDeviceId,
    addr: SocketAddr,
    client_config: quinn::ClientConfig,
    update: Sender<PeerUpdate>,
) -> MainResult<()> {
    match try_connect_to_peer(&(uuid, device_id), addr, client_config).await {
        Ok(stream) => {
            update
                .send(PeerUpdate::NewConnection(
                    stream,
                    peer_uuid,
                    device_id,
                    Side::Client,
                ))
                .await?;
        }
        Err(e) => warn!(
            "Unable to connect with {} for device {} ({:?})",
            peer_uuid, device_id, e
        ),
    }
    Ok(())
}

enum StreamAction {
    AcceptStream(QuinnStream, PeerId, LocalDeviceId, Side),
    RejectStream(QuinnStream, ConnectionStatus),
}

async fn handle_peer_update(
    update: PeerUpdate,
    status: &mut Peers,
) -> MainResult<Option<StreamAction>> {
    match update {
        PeerUpdate::NewConnection(stream, peer_id, device_id, side) => {
            let current = status.get_mut(&(peer_id, device_id));
            let action = match current {
                None => StreamAction::RejectStream(stream, ConnectionStatus::UnknownPeer),
                Some(state) => match state.status() {
                    PeerStates::Disconnected(_) => {
                        state.connect();
                        StreamAction::AcceptStream(stream, peer_id, device_id, side)
                    }
                    PeerStates::Connected(_) => {
                        StreamAction::RejectStream(stream, ConnectionStatus::AlreadyConnected)
                    }
                },
            };
            return Ok(Some(action));
        }
        PeerUpdate::Disconnection(peer_id, device_id, reason) => {
            let current = status.get_mut(&(peer_id, device_id));
            match current {
                None => (),
                Some(state) => {
                    info!(
                        "{} with device {} has disconnected ({})",
                        peer_id, device_id, reason
                    );
                    state.disconnect();
                }
            }
        }
    }
    Ok(None)
}

#[instrument(skip_all)]
pub async fn peer_management_subsystem(
    module_args: PeerManagementArgs,
    monitor: Monitor,
    mut status: Peers,
    send_updates: Sender<PeerUpdate>,
    mut new_stream: Receiver<PeerUpdate>,
    request_qkd: Sender<RequestQkdKeys>,
) -> SubsystemResult {
    loop {
        tokio::select! {
            _ = monitor.cancelled() => {
                return Ok(())
            },
            Some(update) = new_stream.recv() => {
                info!("Peer update: {:?}", update);
                match handle_peer_update(update, &mut status).await {
                    Ok(Some(StreamAction::AcceptStream(mut stream, peer_id, device_id, side))) => {
                        info!("Accepting stream");
                        if let Side::Server = side {
                            info!("Sending Acceptance");
                            send_message(&mut stream, &ConnectionStatus::Accepted).await?;
                        };
                        monitor.run(launch_peer_communication(monitor.clone(), peer_id, device_id, stream, side, send_updates.clone(), request_qkd.clone()));
                    },
                    Ok(Some(StreamAction::RejectStream(mut stream, reason))) => {
                        info!("Rejecting stream: {:?}", reason);
                        send_message(&mut stream, &reason).await?;
                        if let Err(e) = stream.shutdown_streams() {
                            warn!("An error when shutting down stream: {:?}", e)
                        }
                    },
                    Ok(None) => (),
                    Err(e) => return Err(e.into())
                }
            },

            _ = tokio::time::sleep(Duration::from_secs(15)) => {
                    for ((peer_id, device_id), state) in status.iter_mut() {
                if let PeerStates::Disconnected(peer) = state.status() {
                    info!("Trying to connect to ({}, {})", peer_id, device_id);
                    monitor.run(connect_to_peer(module_args.uuid, *peer_id, *device_id, peer.info.addr, module_args.client_config.clone(), send_updates.clone()));
                    }
                };
            }
        }
    }
}

#[instrument(level = "error", skip_all)]
async fn handle_incoming_connection(
    mut stream: QuinnStream,
    remote_to_local: &RemoteToLocal,
) -> Option<PeerUpdate> {
    let mut buff = [0; 1024];
    let result = read_message(&mut stream, &mut buff).await;
    match result {
        Ok((peer_id, remote_device_id)) => match remote_to_local.get(&remote_device_id) {
            Some(device_id) => {
                info!("Connection from {} for device {}", peer_id, device_id);
                Some(PeerUpdate::NewConnection(
                    stream,
                    peer_id,
                    *device_id,
                    Side::Server,
                ))
            }
            None => {
                warn!("No peer has remote device id {}", remote_device_id);
                None
            }
        },
        Err(e) => {
            warn!("Invalid initial message: {:?}", e);
            None
        }
    }
}

#[instrument(level = "info", skip_all)]
pub async fn listen_for_peer_connections(
    local_addr: SocketAddr,
    peer_update: Sender<PeerUpdate>,
    monitor: Monitor,
    server_config: quinn::ServerConfig,
    remote_to_local: RemoteToLocal,
) -> SubsystemResult {
    let listener = quinn::Endpoint::server(server_config, local_addr)?;
    info!("Listening for peer connections on {}", local_addr);
    loop {
        tokio::select! {
            _ = monitor.cancelled() =>  { return Ok(())},
            Some(conn) = listener.accept() => {
                info!("Incoming connection");
                let connection = conn.await.map_err(|e| SubsystemError(format!("Unable to open a connection: {}", e)))?;
                let stream = QuinnStream::accept(connection).await?;
                if let Some(update) = handle_incoming_connection(stream, &remote_to_local).await {
                    peer_update.send(update).await.map_err(|e| SubsystemError(e.to_string()))?;
                }
            }
        }
    }
}

async fn handshake_server(stream: &mut QuinnStream, buff: &mut [u8]) -> MainResult<Role> {
    info!("Handshake start");
    let algos = read_message::<KnownEC>(stream, buff).await?;
    info!("Counterparty knows: {}", algos.join(","));
    let role = if rand::random() {
        Role::Leader
    } else {
        Role::Follower
    };
    let msg = role.opposite();
    send_message(stream, &msg).await?;
    info!("Handshake done. Our role: {:?}", role);
    Ok(role)
}

async fn handshake_client(stream: &mut QuinnStream, buff: &mut [u8]) -> MainResult<Role> {
    info!("Handshake start");
    let mut algos: KnownEC = Vec::new();
    for algo in ["A", "B", "C"] {
        algos.push(algo.to_string());
    }
    send_message(stream, &algos).await?;
    let role = read_message(stream, buff).await?;
    info!("Handshake done. Our role: {:?}", role);
    Ok(role)
}
