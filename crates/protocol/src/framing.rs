use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};
use thiserror::Error;

/// Maximum binary IPC frame size: 64 MiB.
pub const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("EOF while reading frame header")]
    Eof,
    #[error("frame length {0} exceeds max {MAX_FRAME_SIZE}")]
    FrameTooLarge(usize),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("MessagePack encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("MessagePack decode error: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
}

/// Write a 4-byte LE length-prefixed MessagePack frame (named map keys for cross-language stability).
pub fn write_frame_sync<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> Result<(), FrameError> {
    let payload = rmp_serde::to_vec_named(msg)?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge(payload.len()));
    }
    let len = payload.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

/// Read a 4-byte LE length-prefixed MessagePack frame synchronously.
pub fn read_frame_sync<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, FrameError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Eof),
        Err(e) => return Err(FrameError::Io(e)),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(rmp_serde::from_slice(&buf)?)
}

#[cfg(feature = "async-io")]
pub mod async_codec {
    use super::*;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    pub async fn write_frame_async<W: AsyncWrite + Unpin, T: Serialize>(
        writer: &mut W,
        msg: &T,
    ) -> Result<(), FrameError> {
        let payload = rmp_serde::to_vec_named(msg)?;
        if payload.len() > MAX_FRAME_SIZE {
            return Err(FrameError::FrameTooLarge(payload.len()));
        }
        let len = payload.len() as u32;
        writer.write_all(&len.to_le_bytes()).await?;
        writer.write_all(&payload).await?;
        writer.flush().await?;
        Ok(())
    }

    pub async fn read_frame_async<R: AsyncRead + Unpin, T: DeserializeOwned>(
        reader: &mut R,
    ) -> Result<T, FrameError> {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Eof),
            Err(e) => return Err(FrameError::Io(e)),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(FrameError::FrameTooLarge(len));
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        Ok(rmp_serde::from_slice(&buf)?)
    }
}
