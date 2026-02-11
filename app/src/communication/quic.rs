use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::errors::MainResult;

pub struct QuinnStream {
    pub connection: quinn::Connection,
    pub writer: SendStream,
    pub reader: RecvStream,
}

impl QuinnStream {
    pub async fn accept(connection: quinn::Connection) -> MainResult<Self> {
        let (writer, reader) = connection.accept_bi().await?;
        Ok(Self {
            connection,
            reader,
            writer,
        })
    }
    pub async fn connect(connection: quinn::Connection) -> MainResult<Self> {
        let (writer, reader) = connection.open_bi().await?;
        Ok(Self {
            connection,
            reader,
            writer,
        })
    }

    pub fn from_parts(
        connection: quinn::Connection,
        writer: SendStream,
        reader: RecvStream,
    ) -> Self {
        Self {
            connection,
            writer,
            reader,
        }
    }

    pub async fn read_len(&mut self) -> MainResult<u32> {
        Ok(self.reader.read_u32().await?)
    }
    pub async fn read_exact<'a>(&mut self, buf: &'a mut [u8]) -> MainResult<&'a [u8]> {
        self.reader.read_exact(buf).await?;
        Ok(buf)
    }
    pub async fn write_all(&mut self, buf: &[u8]) -> MainResult<()> {
        //let mut stream = self.connection.open_uni().await?;
        self.writer.write(buf).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub fn shutdown_streams(&mut self) -> MainResult<()> {
        self.writer.finish()?;
        self.reader.stop(0u16.into())?;
        Ok(())
    }

    pub fn get_connection(&self) -> quinn::Connection {
        self.connection.clone()
    }
}
