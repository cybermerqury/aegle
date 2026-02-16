// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use super::task_monitor::Monitor;
use std::time::Duration;
use tokio::{
    signal::{self, unix},
    sync::mpsc,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tracing::info;

type Result<E> = std::result::Result<(), E>;
type ResultNested<E> = std::result::Result<Result<E>, E>;

pub struct TaskManager<E> {
    pub spawner: Spawner<E>,
    pub monitor: Monitor,
}

impl<E> TaskManager<E>
where
    E: std::error::Error
        + std::convert::From<tokio::task::JoinError>
        + std::convert::From<std::io::Error>
        + std::marker::Send
        + std::marker::Sync
        + 'static,
{
    pub fn new() -> Self {
        let (send, recv) = mpsc::channel(100);
        let cancellation_token = CancellationToken::new();
        let ts = Spawner {
            sync_sender: send.clone(),
            sync_receiver: recv,
            cancellation_token: cancellation_token.clone(),
            join_set: JoinSet::new(),
        };
        let rm = Monitor::new(send, cancellation_token.clone());
        TaskManager {
            spawner: ts,
            monitor: rm,
        }
    }

    /// Monitors the spawned subsystems without execution ime constraints. Returns a ResultNested
    /// result as per the following pattern:
    /// - Ok(Ok())   - Monitored subsystem/s exited without error.
    ///              - Monitor instance exited without error.
    /// - Ok(Err(e)) - Monitored subsystem/s exited with error.
    ///              - Monitor instance exited without error.
    /// - Err(e)     - Monitored subsystem/s exit status unknown.
    ///              - Monitor instance exited with error.
    pub async fn monitor(mut self) -> ResultNested<E> {
        let mut sigterm = unix::signal(unix::SignalKind::terminate())?;
        let returned_result: Result<E> = tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Ctrl-c signal captured.");
                Ok(())
            }
            _ = sigterm.recv() => {
                info!("Sigterm received");
                Ok(())
             }
            Some(join_return) = self.spawner.join_set.join_next() => {
                join_return?
            }
        };

        drop(self.spawner.sync_sender);
        drop(self.monitor);
        self.spawner.cancellation_token.cancel();
        let _ = self.spawner.sync_receiver.recv().await;

        Ok(returned_result)
    }

    /// Monitors the spawned subsystems with max allowed execution time. Returns a ResultNested
    /// result as per the following pattern:
    /// - Ok(Ok())   - Monitored subsystem/s exited without error.
    ///              - Monitor instance exited without error.
    /// - Ok(Err(e)) - Monitored subsystem/s exited with error.
    ///              - Monitor instance exited without error.
    /// - Err(e)     - Monitored subsystem/s exit status unknown.
    ///              - Monitor instance exited with error.
    pub async fn timed_monitor(mut self, execution_time: Duration) -> ResultNested<E> {
        let returned_result: Result<E> = tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Ctrl-c signal captured.");
                Ok(())
            }
            _ = tokio::time::sleep(execution_time) => {
                info!("Execution time provided has elapsed.");
                Ok(())
            }
            Some(join_return) = self.spawner.join_set.join_next() => {
                join_return?
            }
        };

        drop(self.spawner.sync_sender);
        self.spawner.cancellation_token.cancel();
        let _ = self.spawner.sync_receiver.recv().await;

        Ok(returned_result)
    }
}

impl<E> Default for TaskManager<E>
where
    E: std::error::Error
        + std::convert::From<tokio::task::JoinError>
        + std::marker::Send
        + std::marker::Sync
        + std::convert::From<std::io::Error>
        + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

pub struct Spawner<E> {
    sync_sender: mpsc::Sender<()>,
    cancellation_token: CancellationToken,
    sync_receiver: mpsc::Receiver<()>,
    join_set: JoinSet<Result<E>>,
}

impl<E> Spawner<E>
where
    E: std::error::Error
        + std::convert::From<tokio::task::JoinError>
        + std::marker::Send
        + std::marker::Sync
        + 'static,
{
    pub fn new() -> Self {
        let (send, recv) = mpsc::channel(100);
        Self {
            sync_sender: send,
            sync_receiver: recv,
            cancellation_token: CancellationToken::new(),
            join_set: JoinSet::new(),
        }
    }

    pub fn spawn_subsystem<F>(&mut self, f: F)
    where
        F: std::future::Future<Output = Result<E>> + 'static + Send,
    {
        self.join_set.spawn(f);
    }

    pub fn cancel(&self) {
        self.cancellation_token.cancel();
    }

    pub async fn cancelled(&self) {
        self.cancellation_token.cancelled().await
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation_token.is_cancelled()
    }
}

impl<E> Default for Spawner<E>
where
    E: std::error::Error
        + std::convert::From<tokio::task::JoinError>
        + std::marker::Send
        + std::marker::Sync
        + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

#[macro_export]
macro_rules! call{
    ($f:ident ($($parsed:expr),*)) => {
        $f($($parsed),*)
    };

    ($f:ident () $tm:ident (.monitor,$($args:tt)*)) => {
        $crate::call!($f ($tm.monitor.clone()) $tm ($($args)*))
    };
    ($f:ident () $tm:ident ($a:expr,$($args:tt)*)) => {
        $crate::call!($f ($a) $tm ($($args)*))
    };
    ($f:ident ($($parsed:expr),+) $tm:ident (.monitor)) => {
        $crate::call!($f ($($parsed),+, $tm.monitor.clone()))
    };
    ($f:ident ($($parsed:expr),+) $tm:ident (.monitor,$($args:tt)*)) => {
        $crate::call!($f ($($parsed),+, $tm.monitor.clone(), $($args)*))
    };
    ($f:ident ($($parsed:expr),+) $tm:ident ($a:expr)) => {
        $crate::call!($f ($($parsed),+, $a))
    };
    ($f:ident ($($parsed:expr),+) $tm:ident ($a:expr,$($args:tt)*)) => {
        $crate::call!($f ($($parsed),+, $a) $tm ($($args)*))
    };
}

#[macro_export]
macro_rules! spawn_subsystem {
    ($tm:ident, $fut:ident ($($args:tt)*)) => {
        $tm.spawner.spawn_subsystem($crate::call!($fut () $tm ($($args)*)))
    };
}
