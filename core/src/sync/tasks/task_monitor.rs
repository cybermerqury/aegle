use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Monitor {
    sync_sender: mpsc::Sender<()>,
    cancellation_token: CancellationToken,
}

impl Monitor {
    pub fn new(sync_sender: mpsc::Sender<()>, cancellation_token: CancellationToken) -> Self {
        Self {
            sync_sender,
            cancellation_token,
        }
    }

    pub fn run<F, O>(&self, f: F) -> JoinHandle<O>
    where
        F: std::future::Future<Output = O> + 'static + Send,
        O: 'static + Send,
    {
        let monitor_token = self.build_monitor_token();
        //Move the monitor token into the spawned task.
        //The explicit drop is required otherwise the compiler drops the token before moving
        tokio::spawn(async move {
            let result = f.await;
            drop(monitor_token);
            result
        })
    }

    pub async fn cancelled(&self) {
        self.cancellation_token.cancelled().await
    }

    fn build_monitor_token(&self) -> MonitorToken {
        MonitorToken {
            _sync_sender: self.sync_sender.clone(),
        }
    }
}

pub struct MonitorToken {
    pub _sync_sender: mpsc::Sender<()>,
}
