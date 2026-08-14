// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

pub mod ber_estimation;
pub mod privacy_amplification;
pub mod update_qkd;

mod peer;

use core::generate_uuid_newtype;
use core::key_state_machine::Key;
#[cfg(feature = "ec_simcommsys")]
use ec_simcommsys::{client::SCSApi, config::CodeProperties};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;
#[cfg(feature = "ec_simcommsys")]
use std::sync::Arc;
use uuid::Uuid;

pub use peer::{MutPeerState, PeerInfo, PeerStates};

pub type Peers = HashMap<(PeerId, LocalDeviceId), MutPeerState>;

pub struct PeerManagementArgs {
    pub uuid: OwnID,
    pub client_config: quinn::ClientConfig,
    #[cfg(feature = "ec_simcommsys")]
    pub scs_client: Arc<SCSApi>,
    #[cfg(feature = "ec_simcommsys")]
    pub ldpc_codes: Arc<Vec<CodeProperties>>,
}

generate_uuid_newtype!(DeviceId);
generate_uuid_newtype!(KeyId);
generate_uuid_newtype!(PeerId);
generate_uuid_newtype!(OwnID);

#[derive(Hash, Eq, PartialEq, Serialize, Deserialize, Clone, Copy)]
pub struct RemoteDeviceId(DeviceId);

impl From<DeviceId> for RemoteDeviceId {
    fn from(value: DeviceId) -> Self {
        RemoteDeviceId(value)
    }
}

impl From<Uuid> for RemoteDeviceId {
    fn from(value: Uuid) -> Self {
        RemoteDeviceId(DeviceId::from(value))
    }
}

impl Display for RemoteDeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Hash, Eq, PartialEq, Serialize, Deserialize, Clone, Copy)]
pub struct LocalDeviceId(DeviceId);

impl From<DeviceId> for LocalDeviceId {
    fn from(value: DeviceId) -> Self {
        LocalDeviceId(value)
    }
}

impl From<Uuid> for LocalDeviceId {
    fn from(value: Uuid) -> Self {
        LocalDeviceId(DeviceId::from(value))
    }
}

impl From<LocalDeviceId> for DeviceId {
    fn from(value: LocalDeviceId) -> Self {
        value.0
    }
}

impl Display for LocalDeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

pub type FullId = (KeyId, DeviceId);

pub trait FullKeyId {
    fn device_id(&self) -> DeviceId;
    fn key_id(&self) -> KeyId;
    fn full_id(&self) -> (KeyId, DeviceId) {
        (self.key_id(), self.device_id())
    }
}

impl<T> FullKeyId for Key<T> {
    fn device_id(&self) -> DeviceId {
        DeviceId::from(self.device_id())
    }
    fn key_id(&self) -> KeyId {
        KeyId::from(self.key_id())
    }
}
