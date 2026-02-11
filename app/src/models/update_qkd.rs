use core::key_state_machine::{Key, Sifted};

use super::{LocalDeviceId, PeerId};

type QkdKeysReply = Option<tokio::sync::mpsc::Receiver<Key<Sifted>>>;

pub struct RequestQkdKeys {
    peer_id: PeerId,
    device_id: LocalDeviceId,
    reply: tokio::sync::oneshot::Sender<QkdKeysReply>,
}

impl RequestQkdKeys {
    pub fn new(
        peer_id: PeerId,
        device_id: LocalDeviceId,
    ) -> (Self, tokio::sync::oneshot::Receiver<QkdKeysReply>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        (
            Self {
                peer_id,
                device_id,
                reply: tx,
            },
            rx,
        )
    }
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn device_id(&self) -> &LocalDeviceId {
        &self.device_id
    }

    pub fn reply(self, response: QkdKeysReply) -> Result<(), QkdKeysReply> {
        self.reply.send(response)
    }
}
