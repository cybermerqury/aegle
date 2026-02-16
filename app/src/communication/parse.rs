// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use crate::errors::MainResult;

use super::quic::QuinnStream;

fn from_bytes<'a, T>(bytes: &'a [u8]) -> bincode::Result<T>
where
    T: serde::Deserialize<'a>,
{
    bincode::deserialize::<T>(bytes)
}

fn to_bytes<T>(value: &T) -> bincode::Result<Vec<u8>>
where
    T: serde::Serialize,
{
    bincode::serialize(value)
}
pub async fn read_message<'a, T>(stream: &mut QuinnStream, buff: &'a mut [u8]) -> MainResult<T>
where
    T: serde::Deserialize<'a>,
{
    let n: usize = stream.read_len().await?.try_into()?;
    let bytes = stream.read_exact(buff[..n].as_mut()).await?;
    Ok(from_bytes(bytes)?)
}

pub async fn send_message<T>(stream: &mut QuinnStream, value: &T) -> MainResult<()>
where
    T: serde::Serialize,
{
    let bytes = to_bytes(value)?;
    let n: u32 = bytes.len().try_into()?;
    let buff: Vec<u8> = n
        .to_be_bytes()
        .into_iter()
        .chain(bytes.into_iter())
        .collect();
    stream.write_all(&buff).await?;
    Ok(())
}
