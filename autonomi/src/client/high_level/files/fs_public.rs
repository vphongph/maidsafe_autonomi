// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::archive_public::{ArchiveAddress, PublicArchive};
use super::{DownloadError, FileCostError, Metadata, UploadError};
use crate::AttoTokens;
use crate::client::data_types::chunk::{ChunkAddress, DataMapChunk};
use crate::client::high_level::data::DataAddress;
use crate::client::payment::PaymentOption;
use crate::client::quote::add_costs;
use crate::client::{Client, PutError};
use bytes::Bytes;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

impl Client {
    /// Download file from network to local file system
    pub async fn file_download_public(
        &self,
        data_addr: &DataAddress,
        to_dest: PathBuf,
    ) -> Result<(), DownloadError> {
        info!("Downloading public file to {to_dest:?} from {data_addr:?}");

        let data_map_chunk = DataMapChunk(
            self.chunk_get(&ChunkAddress::new(*data_addr.xorname()))
                .await
                .map_err(DownloadError::GetError)?,
        );

        self.file_download(&data_map_chunk, to_dest).await
    }

    /// Download directory from network to local file system
    pub async fn dir_download_public(
        &self,
        archive_addr: &ArchiveAddress,
        to_dest: PathBuf,
    ) -> Result<(), DownloadError> {
        let archive = self.archive_get_public(archive_addr).await?;
        debug!("Downloaded archive for the directory from the network at {archive_addr:?}");
        for (path, addr, _meta) in archive.iter() {
            self.file_download_public(addr, to_dest.join(path)).await?;
        }
        debug!(
            "All files in the directory downloaded to {:?} from the network address {:?}",
            to_dest.parent(),
            archive_addr
        );
        Ok(())
    }

    /// Upload the content of all files in a directory to the network.
    /// The directory is recursively walked and each file is uploaded to the network.
    ///
    /// The datamaps of these files are uploaded on the network, making the individual files publicly available.
    ///
    /// This returns, but does not upload (!),the [`PublicArchive`] containing the datamaps of the uploaded files.
    pub async fn dir_content_upload_public(
        &self,
        dir_path: PathBuf,
        payment_option: PaymentOption,
    ) -> Result<(AttoTokens, PublicArchive), UploadError> {
        let (total_cost, streams) = self
            .dir_content_upload_internal(dir_path, payment_option, true)
            .await?;

        let mut public_archive = PublicArchive::new();
        for stream in streams {
            let file_path = stream.file_path.clone();
            if let Some(datamap) = stream.data_map_chunk() {
                let data_address = DataAddress::new(*datamap.0.name());
                public_archive.add_file(stream.relative_path, data_address, stream.metadata);
            } else {
                error!("Datamap chunk not found for file: {file_path:?}, this is a BUG");
            }
        }

        for (file_path, data_addr, _meta) in public_archive.iter() {
            info!("Uploaded file: {file_path:?} to: {data_addr}");
            #[cfg(feature = "loud")]
            println!("Uploaded file: {file_path:?} to: {data_addr}");
        }

        Ok((total_cost, public_archive))
    }

    /// Same as [`Client::dir_content_upload_public`] but also uploads the archive to the network.
    ///
    /// Returns the [`ArchiveAddress`] of the uploaded archive.
    pub async fn dir_upload_public(
        &self,
        dir_path: PathBuf,
        payment_option: PaymentOption,
    ) -> Result<(AttoTokens, ArchiveAddress), UploadError> {
        let (cost1, archive) = self
            .dir_content_upload_public(dir_path, payment_option.clone())
            .await?;
        let (cost2, archive_addr) = self.archive_put_public(&archive, payment_option).await?;
        let total_cost = add_costs(cost1, cost2).map_err(PutError::from)?;
        Ok((total_cost, archive_addr))
    }

    /// Upload the content of a file to the network.
    /// Reads file, splits into chunks, uploads chunks, uploads datamap, returns DataAddr (pointing to the datamap)
    pub async fn file_content_upload_public(
        &self,
        path: PathBuf,
        payment_option: PaymentOption,
    ) -> Result<(AttoTokens, DataAddress), UploadError> {
        let (data_map_chunk, processed_chunks, free_chunks, receipts) = self
            .stream_upload_file(path.clone(), payment_option, true)
            .await?;
        let addr = DataAddress::new(*data_map_chunk.0.name());
        let total_cost = self
            .calculate_total_cost(processed_chunks, receipts, free_chunks)
            .await;

        debug!("File {path:?} uploaded to the network at {addr:?}");
        Ok((total_cost, addr))
    }

    /// Get the cost to upload a file/dir to the network.
    /// quick and dirty implementation, please refactor once files are cleanly implemented
    pub async fn file_cost(&self, path: &PathBuf) -> Result<AttoTokens, FileCostError> {
        let mut archive = PublicArchive::new();
        let mut content_addrs = vec![];

        for entry in walkdir::WalkDir::new(path) {
            let entry = entry?;

            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path().to_path_buf();
            tracing::info!("Cost for file: {path:?}");

            let data = tokio::fs::read(&path).await?;
            let file_bytes = Bytes::from(data);

            let addrs = self.get_content_addrs(file_bytes.clone())?;

            // The first addr is always the chunk_map_name
            let map_xor_name = addrs[0].0;

            content_addrs.extend(addrs);

            let metadata = metadata_from_entry(&entry);

            archive.add_file(path, DataAddress::new(map_xor_name), metadata);
        }

        let serialized = archive.to_bytes()?;
        content_addrs.extend(self.get_content_addrs(serialized)?);

        let total_cost = self.get_cost_estimation(content_addrs).await?;
        debug!("Total cost for the directory: {total_cost:?}");
        Ok(total_cost)
    }
}

// Get metadata from directory entry. Defaults to `0` for creation and modification times if
// any error is encountered. Logs errors upon error.
pub(crate) fn metadata_from_entry(entry: &walkdir::DirEntry) -> Metadata {
    let fs_metadata = match entry.metadata() {
        Ok(metadata) => metadata,
        Err(err) => {
            tracing::warn!(
                "Failed to get metadata for `{}`: {err}",
                entry.path().display()
            );
            return Metadata {
                created: 0,
                modified: 0,
                size: 0,
                extra: None,
            };
        }
    };

    let unix_time = |property: &'static str, time: std::io::Result<SystemTime>| {
        time.inspect_err(|err| {
            tracing::warn!(
                "Failed to get '{property}' metadata for `{}`: {err}",
                entry.path().display()
            );
        })
        .unwrap_or(SystemTime::UNIX_EPOCH)
        .duration_since(SystemTime::UNIX_EPOCH)
        .inspect_err(|err| {
            tracing::warn!(
                "'{property}' metadata of `{}` is before UNIX epoch: {err}",
                entry.path().display()
            );
        })
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
    };
    let created = unix_time("created", fs_metadata.created());
    let modified = unix_time("modified", fs_metadata.modified());

    Metadata {
        created,
        modified,
        size: fs_metadata.len(),
        extra: None,
    }
}
