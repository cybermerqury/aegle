// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use serde::Deserialize;
use std::net::SocketAddr;

use ppaas_core::models::DeviceId;

use super::PeerId;

#[derive(Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
pub struct PeerInfo {
    pub uuid: PeerId,
    pub addr: SocketAddr,
    pub qkd: Vec<QkdInfo>,
}

#[derive(Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct Peer<T> {
    pub info: PeerInfo,
    status: T,
}

#[derive(Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
pub struct QkdInfo {
    pub local: DeviceId,
    pub remote: DeviceId,
}

impl Peer<Disconnected> {
    pub fn new(info: PeerInfo) -> Peer<Disconnected> {
        Self {
            info,
            status: Disconnected {},
        }
    }

    fn connect(self) -> Peer<Connected> {
        Peer {
            info: self.info.clone(),
            status: Connected {},
        }
    }
}

impl Peer<Connected> {
    fn disconnect(self) -> Peer<Disconnected> {
        Peer {
            info: self.info.clone(),
            status: Disconnected {},
        }
    }
}

trait PeerStatus {}

pub mod states {
    #[derive(Debug)]
    pub struct Connected;
    #[derive(Debug)]
    pub struct Disconnected;
}

use states::{Connected, Disconnected};

#[derive(Debug)]
pub enum PeerStates {
    Connected(Peer<Connected>),
    Disconnected(Peer<Disconnected>),
}

#[derive(Debug)]
pub struct MutPeerState(Option<PeerStates>);

impl PeerStatus for Connected {}
impl PeerStatus for Disconnected {}

impl PeerStates {
    pub fn new(info: PeerInfo) -> Self {
        Self::Disconnected(Peer::new(info))
    }
}

impl MutPeerState {
    pub fn new(info: PeerInfo) -> Self {
        Self(Some(PeerStates::new(info)))
    }

    pub fn status(&self) -> &PeerStates {
        match self.0 {
            Some(ref state) => state,
            None => unreachable!(),
        }
    }
    pub fn connect(&mut self) {
        let state = self.0.take();
        match state {
            Some(PeerStates::Disconnected(peer)) => {
                self.0.replace(PeerStates::Connected(peer.connect()));
            }
            Some(PeerStates::Connected(_)) => self.0 = state,
            None => unreachable!(),
        }
    }
    pub fn disconnect(&mut self) {
        let state = std::mem::take(&mut self.0);
        match state {
            Some(PeerStates::Connected(peer)) => {
                self.0.replace(PeerStates::Disconnected(peer.disconnect()));
            }
            Some(PeerStates::Disconnected(_)) => {
                self.0 = state;
            }
            None => unreachable!(),
        }
    }
}
