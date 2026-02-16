// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
enum InitialMessage {
    AnnounceUuid(Uuid),
}
