use anyhow::Error;
use async_trait::async_trait;
use futures_lite::{AsyncWrite, AsyncRead};


#[async_trait(?Send)]
pub trait FsImpl: Sized {
    type TempFile;
    type Error: std::fmt::Debug;
    async fn create_tmp_file(&self) -> Result<Self::TempFile, Self::Error>;
    async fn drop_tmp_file(&self, file: Self::TempFile);
}
