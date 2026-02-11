use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
enum InitialMessage {
    AnnounceUuid(Uuid),
}
