// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use bitvec::slice::BitSlice;
use bitvec::vec::BitVec;
use rand::distributions::Uniform;
use rand::prelude::*;
use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tracing::{info, instrument};
use uuid::Uuid;

use core::sync::tasks::Monitor;

use crate::config::{self, Link, Module};
use crate::errors::{EmulatorResult, ErrorMessage, SubsystemResult};

type SendKeys = (quinn::Connection, Uuid);

#[instrument(level="ERROR", skip_all, fields(link=?link))]
pub async fn handle_link(monitor: Monitor, link: Link) -> SubsystemResult {
    info!("Starting link");
    let config = link.client_config()?;
    let (conn_a, conn_b) = tokio::join!(
        try_until_success(monitor.clone(), || {
            create_connection(&link.modules.0, config.clone())
        }),
        try_until_success(monitor.clone(), || {
            create_connection(&link.modules.1, config.clone())
        })
    );
    let conn_a = conn_a?;
    let conn_b = conn_b?;
    let mut vec = vec![(conn_a, link.modules.0.uuid), (conn_b, link.modules.1.uuid)];

    loop {
        tokio::select! {
            _ = monitor.cancelled() => {
                break
            },
            _ = vec[0].0.closed() => {
                info!("Lost connection with: {}", vec[0].1);
                vec[0] = (reconnect(monitor.clone(), &link.modules.0, &config).await?, vec[0].1)
            },

            _ = vec[1].0.closed() => {
                info!("Lost connection with: {}", vec[1].1);
                vec[1] = (reconnect(monitor.clone(), &link.modules.1, &config).await?, vec[1].1)
            },
            _ = tokio::time::sleep(link.frequency) => {
                let (key_a, key_b) = generate_key(link.length, link.error_rate.val());
                let swap = rand::random();
                if swap {
                    vec.reverse()
                }
                send_keys(&vec, &key_a, &key_b, Uuid::new_v4()).await;
                if swap {
                    vec.reverse()
                }
            }
        }
    }
    Ok(())
}

#[instrument(level = "DEBUG", skip_all)]
async fn try_until_success<F, U, T, E>(monitor: Monitor, fut: F) -> EmulatorResult<T>
where
    F: Fn() -> U,
    U: Future<Output = Result<T, E>>,
    E: Debug,
{
    loop {
        tokio::select! {
            _ = monitor.cancelled() => return Err(ErrorMessage("Ctrl-C Received").into()),
        result = fut() => {
            match result {
                Ok(value) => return Ok(value),
                Err(e) => {
                    let mut msg = format!("{:?}", e).to_string();
                    if msg.ends_with('\n') {
                        msg.pop();
                    };
                    info!("Retry because of error: {:?}", msg);
                    monitored_sleep(monitor.clone(), Duration::from_secs(5)).await;
                }
            }
        }
        }
    }
}

async fn create_connection(
    module: &config::Module,
    config: quinn::ClientConfig,
) -> EmulatorResult<quinn::Connection> {
    let endpoint = quinn::Endpoint::client(SocketAddr::from_str("0.0.0.0:0")?)?;
    let connection = endpoint
        .connect_with(config, module.addr, "localhost")?
        .await?;
    info!("Established connection with: {}", module.uuid);
    Ok(connection)
}

async fn reconnect(
    monitor: Monitor,
    module: &Module,
    config: &quinn::ClientConfig,
) -> EmulatorResult<quinn::Connection> {
    try_until_success(monitor.clone(), || {
        create_connection(module, config.clone())
    })
    .await
}

async fn send_keys(vec: &[SendKeys], key1: &BitSlice, key2: &BitSlice, key_id: Uuid) {
    let latency = {
        let mut rng = thread_rng();
        let dist = Uniform::from(Duration::new(0, 0)..Duration::new(1, 0));
        dist.sample(&mut rng)
    };

    for ((conn, uuid), key) in vec.iter().zip([key1, key2]) {
        let _ = send_key_or_log(conn, uuid, key, key_id).await;
        tokio::time::sleep(latency).await;
    }
}

async fn send_key(
    connection: &quinn::Connection,
    uuid: &Uuid,
    key: &BitSlice,
    key_id: Uuid,
) -> EmulatorResult<()> {
    let mut stream = connection.open_uni().await?;
    stream
        .write_all(&bincode::serialize(&(key_id, uuid, key))?)
        .await?;
    stream.finish()?;
    Ok(())
}

async fn send_key_or_log(
    connection: &quinn::Connection,
    uuid: &Uuid,
    key: &BitSlice,
    key_id: Uuid,
) {
    match send_key(connection, uuid, key, key_id).await {
        Ok(()) => info!("Sent key"),
        Err(e) => info!("Unable to send key: {:?}", e),
    }
}

fn generate_key(length: usize, p_error: f64) -> (BitVec, BitVec) {
    let mut k1: BitVec = BitVec::with_capacity(length);
    let mut k2: BitVec = BitVec::with_capacity(length);
    let mut rng = thread_rng();
    for _ in 0..length {
        let val = rng.gen();
        k1.push(val);
        if rng.gen_range(0.0..1.0) < p_error {
            k2.push(!val)
        } else {
            k2.push(val)
        }
    }
    (k1, k2)
}

pub async fn monitored_sleep(monitor: Monitor, duration: Duration) {
    tokio::select! {
        _ = monitor.cancelled() => (),
        _ = tokio::time::sleep(duration) => (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keys() {
        let (k1, k2) = generate_key(1000, 0.1);
        let errs = k1
            .iter()
            .zip(k2.iter())
            .map(|(v1, v2)| if v1 == v2 { 0 } else { 1 })
            .sum::<usize>();
        assert!((10..=500).contains(&errs))
    }
}
