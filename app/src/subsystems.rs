// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

mod peer_communication;
mod qkd_communication;
mod role;

use std::collections::HashMap;

use core::sync::tasks::Monitor;
use core::{spawn_subsystem, sync::tasks::TaskManager};
#[cfg(feature = "ec_simcommsys")]
use ec_simcommsys::client::SCSApi;
#[cfg(feature = "ec_simcommsys")]
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tracing::error;

use crate::config::ModuleConfig;
use crate::errors::{MainResult, SubsystemError, SubsystemResult};
use crate::models::{LocalDeviceId, MutPeerState, PeerManagementArgs, RemoteDeviceId};

use peer_communication::{listen_for_peer_connections, peer_management_subsystem};
use qkd_communication::qkd_manager;

type RemoteToLocal = HashMap<RemoteDeviceId, LocalDeviceId>;

// wait_for_panic subsystem ensures clean shutdown if any panic is raised
async fn wait_for_panic(monitor: Monitor, mut panic_receiver: Receiver<()>) -> SubsystemResult {
    tokio::select! {
        _ = monitor.cancelled() => Ok(()),
        _ = panic_receiver.recv() => Err(SubsystemError("We have a panic!".into()))
    }
}

pub fn start_subsystems(config: ModuleConfig) -> MainResult<TaskManager<SubsystemError>> {
    let module = config.module;
    let mut tm = TaskManager::new();
    let mut status = HashMap::new();
    let mut peer_device = HashMap::new();
    let (send_new_stream, recv_new_stream) = tokio::sync::mpsc::channel(1024);
    let mut remote_to_local = HashMap::new();

    for peer_info in config.peers {
        let peer_uuid = peer_info.uuid;
        let mut qkds = Vec::new();
        for qkd_info in &peer_info.qkd {
            qkds.push(qkd_info.local.into());
            remote_to_local.insert(qkd_info.remote.into(), qkd_info.local.into());
            status.insert(
                (peer_uuid, qkd_info.local.into()),
                MutPeerState::new(peer_info.clone()),
            );
        }
        peer_device.insert(peer_uuid, qkds);
    }

    let module_args = PeerManagementArgs {
        uuid: module.uuid,
        client_config: module.client_config()?,
        #[cfg(feature = "ec_simcommsys")]
        scs_client: Arc::new(SCSApi::new(&config.simcommsys.base_url)?),
        #[cfg(feature = "ec_simcommsys")]
        ldpc_codes: config.simcommsys.ldpc_codes,
    };

    let (qkd_sender, qkd_receiver) = tokio::sync::mpsc::channel(1024);
    let (panic_sender, panic_recv) = tokio::sync::mpsc::channel::<()>(1024);

    let handle_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        error!("Panic detected: {}", panic_info);
        handle_panic(panic_info);
        let _ = panic_sender.clone().try_send(());
    }));

    spawn_subsystem!(tm, wait_for_panic(.monitor, panic_recv));

    spawn_subsystem!(tm, peer_management_subsystem(module_args, .monitor, status, send_new_stream.clone(), recv_new_stream, qkd_sender));

    let config = module.server_config()?;
    spawn_subsystem!(tm, listen_for_peer_connections(module.peer_addr, send_new_stream.clone(), .monitor, config, remote_to_local));
    spawn_subsystem!(tm, qkd_manager(.monitor, module.qkd_addr, module.server_config()?,peer_device, qkd_receiver));
    Ok(tm)
}
