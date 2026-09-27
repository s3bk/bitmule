
struct NativeImpl;

#[async_trait]
impl FsImpl for NativeImpl {
    type TempFile = NativeTempFile;
    async fn create_tmp_file(&self) -> Result<Self::TempFile, Error> {
        let tmp = tempfile::NamedTempFile::new()?;
        let tmp_path = tmp.path().to_path_buf();
        let file = tokio::fs::File::create(&tmp_path).await?;
        Ok(NativeTempFile { tmp, file })
    }
    async fn drop_tmp_file(&self, file: Self::TempFile) {

    }
}
impl NativeTempFile {
    fn file(self: Pin<&mut Self>) -> Pin<&mut tokio::fs::File> {
        // This is okay because `field` is pinned when `self` is.
        unsafe { self.map_unchecked_mut(|s| &mut s.file) }
    }
}

struct NativeTempFile {
    tmp: NamedTempFile,
    file: File,
}
impl AsyncWrite for NativeTempFile {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>>
    {
        self.file().poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        self.file().poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        self.file().poll_shutdown(cx)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>>
    {
        self.file().poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.file.is_write_vectored()
    }
}
