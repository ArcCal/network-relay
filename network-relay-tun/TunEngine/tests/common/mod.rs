use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};
pub struct Device {
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    outgoing: mpsc::UnboundedSender<Vec<u8>>,
}
pub fn device() -> (Device, mpsc::UnboundedSender<Vec<u8>>, mpsc::UnboundedReceiver<Vec<u8>>) {
    let (tx, incoming) = mpsc::unbounded_channel();
    let (outgoing, rx) = mpsc::unbounded_channel();
    (Device { incoming, outgoing }, tx, rx)
}
impl AsyncRead for Device {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.incoming.poll_recv(cx) {
            Poll::Ready(Some(packet)) if packet.len() <= out.remaining() => {
                out.put_slice(&packet);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(_)) => Poll::Ready(Err(io::ErrorKind::InvalidData.into())),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}
impl AsyncWrite for Device {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(self.outgoing.send(data.to_vec()).map(|_| data.len()).map_err(|_| io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
