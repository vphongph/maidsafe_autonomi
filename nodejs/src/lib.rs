use std::{path::PathBuf, str::FromStr};

use autonomi::{
    chunk::DataMapChunk,
    client::{data::DataAddress, payment::PaymentOption},
    files::{
        archive_private::PrivateArchiveDataMap, archive_public::ArchiveAddress, PrivateArchive,
        PublicArchive,
    },
    pointer::PointerTarget,
    register::{RegisterAddress, RegisterHistory, RegisterValue},
    vault::{UserData, VaultContentType, VaultSecretKey},
    AttoTokens, Bytes, Chunk, ChunkAddress, Client, GraphEntry, GraphEntryAddress, Network,
    Pointer, PointerAddress, PublicKey, Scratchpad, ScratchpadAddress, SecretKey, Wallet, XorName,
};

use libp2p::Multiaddr;
use napi::bindgen_prelude::*;
use napi_derive::napi;

// Convert Rust errors to JavaScript errors
fn map_error<E>(err: E) -> napi::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    let err = eyre::Report::new(err);
    napi::Error::new(Status::GenericFailure, format!("{:?}", err))
}

/// Represents a client for the Autonomi network.
#[napi(js_name = "Client")]
pub struct JsClient(Client);

#[napi]
impl JsClient {
    /// Initialize the client with default configuration.
    ///
    /// See `init_with_config`.
    #[napi(factory)]
    pub async fn init() -> Result<Self> {
        let client = Client::init().await.map_err(map_error)?;

        Ok(Self(client))
    }

    /// Initialize a client that is configured to be local.
    ///
    /// See `init_with_config`.
    #[napi(factory)]
    pub async fn init_local() -> Result<Self> {
        let client = Client::init_local().await.map_err(map_error)?;

        Ok(Self(client))
    }

    /// Initialize a client that bootstraps from a list of peers.
    ///
    /// If any of the provided peers is a global address, the client will not be local.
    #[napi]
    pub async fn init_with_peers(peers: Vec<String>) -> Result<Self> {
        let peers = peers
            .iter()
            .map(|p| Multiaddr::from_str(p))
            .collect::<std::result::Result<Vec<Multiaddr>, _>>()
            .map_err(map_error)?;

        let client = Client::init_with_peers(peers).await.map_err(map_error)?;

        Ok(Self(client))
    }

    // /// Initialize the client with the given configuration.
    // ///
    // /// This will block until CLOSE_GROUP_SIZE have been added to the routing table.
    // ///
    // /// See ClientConfig.
    // #[napi]
    // pub async fn init_with_config(config: ClientConfig) -> Result<Self> {
    //     todo!()
    // }

    #[napi]
    pub fn evm_network(&self) -> JsNetwork {
        JsNetwork(self.0.evm_network().clone())
    }

    // Chunks

    /// Get a chunk from the network.
    #[napi]
    pub async fn chunk_get(&self, addr: &JsChunkAddress) -> Result<Buffer> {
        let chunk = self.0.chunk_get(&addr.0).await.map_err(map_error)?;

        Ok(Buffer::from(chunk.value.to_vec()))
    }

    /// Manually upload a chunk to the network.
    ///
    /// It is recommended to use the `data_put` method instead to upload data.
    #[napi]
    pub async fn chunk_put(
        &self,
        data: Buffer,
        payment_option: &JsPaymentOption,
    ) -> Result<tuple_result::ChunkPut> {
        let chunk = Chunk::new(Bytes::from(data.as_ref().to_vec()));

        let (cost, addr) = self
            .0
            .chunk_put(&chunk, payment_option.0.clone())
            .await
            .map_err(map_error)?;

        Ok(tuple_result::ChunkPut { cost, addr })
    }

    /// Get the cost of a chunk.
    #[napi]
    pub async fn chunk_cost(&self, addr: &JsChunkAddress) -> Result</* AttoTokens */ String> {
        let cost = self.0.chunk_cost(&addr.0).await.map_err(map_error)?;

        Ok(cost.to_string())
    }

    // /// Upload chunks and retry failed uploads up to RETRY_ATTEMPTS times.
    // #[napi]
    // pub async fn upload_chunks_with_retries(&self, chunks: Vec<Chunk>, receipt: &Receipt) -> Vec<(Chunk, PutError)> {
    //     todo!()
    // }

    // Graph entries

    /// Fetches a GraphEntry from the network.
    #[napi]
    pub async fn graph_entry_get(&self, address: &JsGraphEntryAddress) -> Result<JsGraphEntry> {
        let graph_entry = self
            .0
            .graph_entry_get(&address.0)
            .await
            .map_err(map_error)?;

        Ok(JsGraphEntry(graph_entry))
    }

    /// Check if a graph_entry exists on the network
    #[napi]
    pub async fn graph_entry_check_existance(&self, address: &JsGraphEntryAddress) -> Result<bool> {
        let exists = self
            .0
            .graph_entry_check_existance(&address.0)
            .await
            .map_err(map_error)?;

        Ok(exists)
    }

    /// Manually puts a GraphEntry to the network.
    #[napi]
    pub async fn graph_entry_put(
        &self,
        entry: &JsGraphEntry,
        payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsGraphEntryAddress) */ tuple_result::GraphEntryPut> {
        let (cost, addr) = self
            .0
            .graph_entry_put(entry.0.clone(), payment_option.0.clone())
            .await
            .map_err(map_error)?;

        Ok(tuple_result::GraphEntryPut { cost, addr })
    }

    /// Get the cost to create a GraphEntry
    #[napi]
    pub async fn graph_entry_cost(&self, key: &JsPublicKey) -> Result</* AttoTokens */ String> {
        let cost = self.0.graph_entry_cost(&key.0).await.map_err(map_error)?;

        Ok(cost.to_string())
    }

    // Pointers

    /// Get a pointer from the network
    #[napi]
    pub async fn pointer_get(&self, _address: &JsPointerAddress) -> Result<JsPointer> {
        todo!()
    }

    /// Check if a pointer exists on the network
    #[napi]
    pub async fn pointer_check_existance(&self, _address: &JsPointerAddress) -> Result<bool> {
        todo!()
    }

    /// Verify a pointer
    #[napi]
    pub fn pointer_verify(_pointer: &JsPointer) -> Result<()> {
        todo!()
    }

    /// Manually store a pointer on the network
    #[napi]
    pub async fn pointer_put(
        &self,
        _pointer: &JsPointer,
        _payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsPointerAddress) */ tuple_result::PointerPut> {
        todo!()
    }

    /// Create a new pointer on the network.
    ///
    /// Make sure that the owner key is not already used for another pointer as each key is associated with one pointer
    #[napi]
    pub async fn pointer_create(
        &self,
        _owner: &JsSecretKey,
        _target: &JsPointerTarget,
        _payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsPointerAddress) */ tuple_result::PointerPut> {
        todo!()
    }

    /// Update an existing pointer to point to a new target on the network.
    ///
    /// The pointer needs to be created first with Client::pointer_put.
    /// This operation is free as the pointer was already paid for at creation.
    /// Only the latest version of the pointer is kept on the Network,
    /// previous versions will be overwritten and unrecoverable.
    #[napi]
    pub async fn pointer_update(
        &self,
        _owner: &JsSecretKey,
        _target: &JsPointerTarget,
    ) -> Result<()> {
        todo!()
    }

    /// Calculate the cost of storing a pointer
    #[napi]
    pub async fn pointer_cost(&self, key: &JsPublicKey) -> Result</* AttoTokens */ String> {
        let cost = self.0.pointer_cost(&key.0).await.map_err(map_error)?;

        Ok(cost.to_string())
    }

    // Scratchpad

    /// Get Scratchpad from the Network. A Scratchpad is stored at the owner's public key so we can derive the address from it.
    #[napi]
    pub async fn scratchpad_get_from_public_key(
        &self,
        _public_key: &JsPublicKey,
    ) -> Result<JsScratchpad> {
        todo!()
    }

    /// Get Scratchpad from the Network
    #[napi]
    pub async fn scratchpad_get(&self, _address: &JsScratchpadAddress) -> Result<JsScratchpad> {
        todo!()
    }

    /// Check if a scratchpad exists on the network
    #[napi]
    pub async fn scratchpad_check_existance(&self, _address: &JsScratchpadAddress) -> Result<bool> {
        todo!()
    }

    /// Verify a scratchpad
    #[napi]
    pub fn scratchpad_verify(_scratchpad: &JsScratchpad) -> Result<()> {
        todo!()
    }

    /// Manually store a scratchpad on the network
    #[napi]
    pub async fn scratchpad_put(
        &self,
        _scratchpad: &JsScratchpad,
        _payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsScratchpadAddress) */ tuple_result::ScratchpadPut> {
        todo!()
    }

    /// Create a new scratchpad to the network.
    ///
    /// Make sure that the owner key is not already used for another scratchpad as each key is associated with one scratchpad. The data will be encrypted with the owner key before being stored on the network. The content type is used to identify the type of data stored in the scratchpad, the choice is up to the caller.
    ///
    /// Returns the cost and the address of the scratchpad.
    #[napi]
    pub async fn scratchpad_create(
        &self,
        _owner: &JsSecretKey,
        _content_type: i64, // `u64`
        _initial_data: Buffer,
        _payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsScratchpadAddress) */ tuple_result::ScratchpadPut> {
        todo!()
    }

    /// Update an existing scratchpad to the network.
    /// The scratchpad needs to be created first with Client::scratchpad_create.
    /// This operation is free as the scratchpad was already paid for at creation.
    /// Only the latest version of the scratchpad is kept on the Network,
    /// previous versions will be overwritten and unrecoverable.
    #[napi]
    pub async fn scratchpad_update(
        &self,
        _owner: &JsSecretKey,
        _content_type: i64, // `u64`
        _data: Buffer,
    ) -> Result<()> {
        todo!()
    }

    /// Get the cost of creating a new Scratchpad
    #[napi]
    pub async fn scratchpad_cost(&self, owner: &JsPublicKey) -> Result</* AttoTokens */ String> {
        let cost = self.0.scratchpad_cost(&owner.0).await.map_err(map_error)?;

        Ok(cost.to_string())
    }

    // Data

    /// Fetch a blob of (private) data from the network
    #[napi]
    pub async fn data_get(&self, data_map: &JsDataMapChunk) -> Result<Buffer> {
        let data = self.0.data_get(&data_map.0).await.map_err(map_error)?;

        Ok(Buffer::from(data.as_ref()))
    }

    /// Upload a piece of private data to the network. This data will be self-encrypted.
    /// The DataMapChunk is not uploaded to the network, keeping the data private.
    ///
    /// Returns the DataMapChunk containing the map to the encrypted chunks.
    #[napi]
    pub async fn data_put(
        &self,
        data: Buffer,
        payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsDataMapChunk) */ tuple_result::DataPutResult> {
        let data = Bytes::copy_from_slice(data.as_ref());

        let (cost, data_map) = self
            .0
            .data_put(data, payment_option.0.clone())
            .await
            .map_err(map_error)?;

        Ok(tuple_result::DataPutResult { cost, data_map })
    }

    /// Fetch a blob of data from the network
    #[napi]
    pub async fn data_get_public(&self, addr: &JsDataAddress) -> Result<Buffer> {
        let data = self.0.data_get_public(&addr.0).await.map_err(map_error)?;

        Ok(Buffer::from(data.as_ref()))
    }

    /// Upload a piece of data to the network. This data is publicly accessible.
    ///
    /// Returns the Data Address at which the data was stored.
    #[napi]
    pub async fn data_put_public(
        &self,
        data: Buffer,
        payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsDataAddress) */ tuple_result::DataPutPublicResult> {
        let data = Bytes::copy_from_slice(data.as_ref());

        let (cost, addr) = self
            .0
            .data_put_public(data, payment_option.0.clone())
            .await
            .map_err(map_error)?;

        Ok(tuple_result::DataPutPublicResult { cost, addr })
    }

    /// Get the estimated cost of storing a piece of data.
    #[napi]
    pub async fn data_cost(&self, data: Buffer) -> Result</* AttoTokens */ String> {
        let cost = self
            .0
            .data_cost(Bytes::copy_from_slice(&data))
            .await
            .map_err(map_error)?;

        Ok(cost.to_string())
    }

    // Archives

    /// Fetch a PrivateArchive from the network
    #[napi]
    pub async fn archive_get(&self, addr: &JsPrivateArchiveDataMap) -> Result<JsPrivateArchive> {
        let archive = self.0.archive_get(&addr.0).await.map_err(map_error)?;

        Ok(JsPrivateArchive(archive))
    }

    /// Upload a PrivateArchive to the network
    #[napi]
    pub async fn archive_put(
        &self,
        _archive: &JsPrivateArchive,
        _payment_option: &JsPaymentOption,
    ) -> Result</*(AttoTokens, JsPrivateArchiveDataMap)*/ tuple_result::ArchivePutResult> {
        todo!()
    }

    // <TOPIC>

    /// Fetch an archive from the network
    #[napi]
    pub async fn archive_get_public(&self, addr: &JsArchiveAddress) -> Result<JsPublicArchive> {
        let archive = self
            .0
            .archive_get_public(&addr.0)
            .await
            .map_err(map_error)?;

        Ok(JsPublicArchive(archive))
    }

    /// Upload an archive to the network
    #[napi]
    pub async fn archive_put_public(
        &self,
        _archive: &JsPublicArchive,
        _payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsArchiveAddress) */ tuple_result::ArchivePutPublicResult> {
        todo!()
    }

    /// Get the cost to upload an archive
    #[napi]
    pub async fn archive_cost(&self, archive: &JsPublicArchive) -> Result</* AttoTokens */ String> {
        let cost = self
            .0
            .archive_cost(&archive.0.clone())
            .await
            .map_err(map_error)?;

        Ok(cost.to_string())
    }

    // Files

    /// Download a private file from network to local file system
    #[napi]
    pub async fn file_download(
        &self,
        _data_access: &JsDataMapChunk,
        _to_dest: /* PathBuf */ String,
    ) -> Result<()> {
        todo!()
    }

    /// Download a private directory from network to local file system
    #[napi]
    pub async fn dir_download(
        &self,
        _archive_access: &JsPrivateArchiveDataMap,
        _to_dest: /* PathBuf */ String,
    ) -> Result<()> {
        todo!()
    }

    /// Upload the content of all files in a directory to the network.
    /// The directory is recursively walked and each file is uploaded to the network.
    ///
    /// The data maps of these (private) files are not uploaded but returned within
    /// the PrivateArchive return type.

    #[napi]
    pub async fn dir_content_upload(
        &self,
        _dir_path: /* PathBuf */ String,
        _payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsPrivateArchive) */ tuple_result::DirContentUpload> {
        todo!()
    }

    /// Same as Client::dir_content_upload but also uploads the archive (privately) to the network.
    ///
    /// Returns the PrivateArchiveDataMap allowing the private archive to be downloaded from the network.
    #[napi]
    pub async fn dir_upload(
        &self,
        _dir_path: /* PathBuf */ String,
        _payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsPrivateArchiveDataMap) */ tuple_result::DirUpload> {
        todo!()
    }

    /// Upload the content of a private file to the network. Reads file, splits into
    /// chunks, uploads chunks, uploads datamap, returns DataMapChunk (pointing to the datamap)
    #[napi]
    pub async fn file_content_upload(
        &self,
        _path: /* PathBuf */ String,
        _payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsDataMapChunk) */ tuple_result::FileContentUpload> {
        todo!()
    }

    /// Download file from network to local file system
    #[napi]
    pub async fn file_download_public(
        &self,
        _data_addr: &JsDataAddress,
        _to_dest: /* PathBuf */ String,
    ) -> Result<()> {
        todo!()
    }

    /// Download directory from network to local file system
    #[napi]
    pub async fn dir_download_public(
        &self,
        _archive_addr: &JsArchiveAddress,
        _to_dest: /* PathBuf */ String,
    ) -> Result<()> {
        todo!()
    }

    /// Upload the content of all files in a directory to the network. The directory is recursively walked and each file is uploaded to the network.
    ///
    /// The data maps of these files are uploaded on the network, making the individual files publicly available.
    ///
    /// This returns, but does not upload (!),the PublicArchive containing the data maps of the uploaded files.
    #[napi]
    pub async fn dir_content_upload_public(
        &self,
        _dir_path: /* PathBuf */ String,
        _payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsPublicArchive) */ tuple_result::DirContentUploadPublic> {
        todo!()
    }

    /// Same as Client::dir_content_upload_public but also uploads the archive to the network.
    ///
    /// Returns the ArchiveAddress of the uploaded archive.
    #[napi]
    pub async fn dir_upload_public(
        &self,
        _dir_path: /* PathBuf */ String,
        _payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsArchiveAddress) */ tuple_result::DirUploadPublic> {
        todo!()
    }

    /// Upload the content of a file to the network. Reads file, splits into chunks,
    /// uploads chunks, uploads datamap, returns DataAddr (pointing to the datamap)
    #[napi]
    pub async fn file_content_upload_public(
        &self,
        _path: /* PathBuf */ String,
        _payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsDataAddress) */ tuple_result::FileContentUploadPublic> {
        todo!()
    }

    /// Get the cost to upload a file/dir to the network. quick and dirty implementation, please refactor once files are cleanly implemented
    #[napi]
    pub async fn file_cost(&self, path: /* &PathBuf */ String) -> Result</* AttoTokens */ String> {
        let cost = self
            .0
            .file_cost(&PathBuf::from(path))
            .await
            .map_err(map_error)?;

        Ok(cost.to_string())
    }

    // Vault/user data

    /// Get the user data from the vault
    #[napi]
    pub async fn get_user_data_from_vault(
        &self,
        _secret_key: &JsVaultSecretKey,
    ) -> Result<JsUserData> {
        todo!()
    }

    /// Put the user data to the vault
    ///
    /// Returns the total cost of the put operation
    #[napi]
    pub async fn put_user_data_to_vault(
        &self,
        _secret_key: &JsVaultSecretKey,
        _payment_option: &JsPaymentOption,
        _user_data: &JsUserData,
    ) -> Result</* AttoTokens */ String> {
        todo!()
    }

    /// Retrieves and returns a decrypted vault if one exists.
    ///
    /// Returns the content type of the bytes in the vault.
    #[napi]
    pub async fn fetch_and_decrypt_vault(
        &self,
        _secret_key: &JsVaultSecretKey,
    ) -> Result</* (Bytes, JsVaultContentType) */ tuple_result::FetchAndDecryptVault> {
        todo!()
    }

    /// Get the cost of creating a new vault A quick estimation of cost:
    /// num_of_graph_entry * graph_entry_cost + num_of_scratchpad * scratchpad_cost
    #[napi]
    pub async fn vault_cost(
        &self,
        owner: &JsVaultSecretKey,
        max_size: /* u64 */ BigInt,
    ) -> Result</* AttoTokens */ String> {
        let (_signed, max_size, losless) = max_size.get_u64();
        if losless {
            return Err(napi::Error::new(
                Status::InvalidArg,
                "`max_size` is too large",
            ));
        }

        let cost = self
            .0
            .vault_cost(&owner.0.clone(), max_size)
            .await
            .map_err(map_error)?;

        Ok(cost.to_string())
    }

    /// Put data into the client’s VaultPacket
    ///
    /// Dynamically expand the vault capacity by paying for more space (Scratchpad) when needed.
    ///
    /// It is recommended to use the hash of the app name or unique identifier as the content type.

    #[napi]
    pub async fn write_bytes_to_vault(
        &self,
        _data: Buffer,
        _payment_option: &JsPaymentOption,
        _secret_key: &JsVaultSecretKey,
        _content_type: &JsVaultContentType,
    ) -> Result</* AttoTokens */ String> {
        todo!()
    }

    // Registers

    /// Get the register history, starting from the root to the latest entry.
    ///
    /// This returns a RegisterHistory that can be use to get the register values from the history.
    ///
    /// RegisterHistory::next can be used to get the values one by one, from the first to the latest entry.
    /// RegisterHistory::collect can be used to get all the register values from the history from the first to the latest entry.
    #[napi]
    pub fn register_history(&self, _addr: &JsRegisterAddress) -> JsRegisterHistory {
        todo!()
    }

    /// Create a new register key from a SecretKey and a name.
    ///
    /// This derives a new SecretKey from the owner’s SecretKey using the name. Note that you will need to keep track of the names you used to create the register key.
    #[napi]
    pub fn register_key_from_name(_owner: &JsSecretKey, _name: String) -> JsSecretKey {
        todo!()
    }

    /// Create a new RegisterValue from bytes, make sure the bytes are not longer than REGISTER_VALUE_SIZE
    #[napi]
    pub fn register_value_from_bytes(_bytes: &[u8]) -> Result<JsRegisterValue> {
        todo!()
    }

    /// Create a new register with an initial value.
    ///
    /// Note that two payments are required, one for the underlying GraphEntry and one for the crate::Pointer
    #[napi]
    pub async fn register_create(
        &self,
        _owner: &JsSecretKey,
        _initial_value: &JsRegisterValue,
        _payment_option: &JsPaymentOption,
    ) -> Result</* (AttoTokens, JsRegisterAddress) */ tuple_result::RegisterCreate> {
        todo!()
    }

    /// Update the value of a register.
    ////
    /// The register needs to be created first with Client::register_create
    #[napi]
    pub async fn register_update(
        &self,
        _owner: &JsSecretKey,
        _new_value: &JsRegisterValue,
        _payment_option: &JsPaymentOption,
    ) -> Result</* AttoTokens */ String> {
        todo!()
    }

    /// Get the current value of the register
    #[napi]
    pub async fn register_get(&self, _addr: &JsRegisterAddress) -> Result<JsRegisterValue> {
        todo!()
    }

    /// Get the cost of a register operation. Returns the cost of creation if it doesn’t exist, else returns the cost of an update
    #[napi]
    pub async fn register_cost(&self, owner: &JsPublicKey) -> Result</* AttoTokens */ String> {
        let cost = self
            .0
            .register_cost(&owner.0.clone())
            .await
            .map_err(map_error)?;

        Ok(cost.to_string())
    }

    // Quotes

    // /// Get raw quotes from nodes. These quotes do not include actual record prices. You will likely want to use get_store_quotes instead.
    // #[napi]
    // pub async fn get_raw_quotes(
    //     &self,
    //     data_type: DataTypes,
    //     content_addrs: impl Iterator<Item = (XorName, usize)>,
    // ) -> Vec<Result<(XorName, Vec<(PeerId, PaymentQuote)>)>> {
    //     todo!()
    // }

    // ///
    // #[napi]
    // pub async fn get_store_quotes(
    //     &self,
    //     data_type: DataTypes,
    //     content_addrs: impl Iterator<Item = (XorName, usize)>,
    // ) -> Result<StoreQuote> {
    //     todo!()
    // }
}

pub mod tuple_result {
    use super::*;

    // This type exists because NAPI-RS does not support returning tuples.
    #[napi]
    pub struct ChunkPut {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: ChunkAddress, // Can't be `JsChunkAddress` as NAPI-RS expects a reference in that case.
    }
    #[napi]
    impl ChunkPut {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsChunkAddress {
            JsChunkAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct GraphEntryPut {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: GraphEntryAddress,
    }
    #[napi]
    impl GraphEntryPut {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsGraphEntryAddress {
            JsGraphEntryAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct ScratchpadPut {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: ScratchpadAddress,
    }
    #[napi]
    impl ScratchpadPut {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsScratchpadAddress {
            JsScratchpadAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct PointerPut {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: PointerAddress,
    }
    #[napi]
    impl PointerPut {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsPointerAddress {
            JsPointerAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct DataPutResult {
        pub(crate) cost: AttoTokens,
        pub(crate) data_map: DataMapChunk,
    }
    #[napi]
    impl DataPutResult {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn data_map(&self) -> JsDataMapChunk {
            JsDataMapChunk(self.data_map.clone())
        }
    }

    #[napi]
    pub struct DataPutPublicResult {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: DataAddress,
    }
    #[napi]
    impl DataPutPublicResult {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsDataAddress {
            JsDataAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct ArchivePutResult {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: PointerAddress,
    }
    #[napi]
    impl ArchivePutResult {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsPointerAddress {
            JsPointerAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct ArchivePutPublicResult {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: PointerAddress,
    }
    #[napi]
    impl ArchivePutPublicResult {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsPointerAddress {
            JsPointerAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct DirContentUpload {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: PointerAddress,
    }
    #[napi]
    impl DirContentUpload {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsPointerAddress {
            JsPointerAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct DirUpload {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: PointerAddress,
    }
    #[napi]
    impl DirUpload {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsPointerAddress {
            JsPointerAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct FileContentUpload {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: PointerAddress,
    }
    #[napi]
    impl FileContentUpload {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsPointerAddress {
            JsPointerAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct DirContentUploadPublic {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: PointerAddress,
    }
    #[napi]
    impl DirContentUploadPublic {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsPointerAddress {
            JsPointerAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct DirUploadPublic {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: PointerAddress,
    }
    #[napi]
    impl DirUploadPublic {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsPointerAddress {
            JsPointerAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct FileContentUploadPublic {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: PointerAddress,
    }
    #[napi]
    impl FileContentUploadPublic {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsPointerAddress {
            JsPointerAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct FetchAndDecryptVault {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: PointerAddress,
    }
    #[napi]
    impl FetchAndDecryptVault {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsPointerAddress {
            JsPointerAddress(self.addr.clone())
        }
    }

    #[napi]
    pub struct RegisterCreate {
        pub(crate) cost: AttoTokens,
        pub(crate) addr: PointerAddress,
    }
    #[napi]
    impl RegisterCreate {
        #[napi(getter)]
        pub fn cost(&self) -> String {
            self.cost.to_string()
        }
        #[napi(getter)]
        pub fn addr(&self) -> JsPointerAddress {
            JsPointerAddress(self.addr.clone())
        }
    }
}

/// A 256-bit number, viewed as a point in XOR space.
///
/// This wraps an array of 32 bytes, i. e. a number between 0 and 2<sup>256</sup> - 1.
///
/// XOR space is the space of these numbers, with the [XOR metric][1] as a notion of distance,
/// i. e. the points with IDs `x` and `y` are considered to have distance `x xor y`.
///
/// [1]: https://en.wikipedia.org/wiki/Kademlia#System_details
#[napi(js_name = "XorName")]
pub struct JsXorName(XorName);
#[napi]
impl JsXorName {
    /// Generate a XorName for the given content.
    #[napi(factory)]
    pub fn from_content(content: &[u8]) -> Self {
        Self(XorName::from_content_parts(&[content]))
    }
}

/// Address of a chunk.
///
/// It is derived from the content of the chunk.
#[napi(js_name = "ChunkAddress")]
pub struct JsChunkAddress(ChunkAddress);

#[napi]
impl JsChunkAddress {
    /// Creates a new ChunkAddress.
    #[napi(constructor)]
    pub fn new(xor_name: &JsXorName) -> Self {
        Self(ChunkAddress::new(xor_name.0.clone()))
    }

    /// Returns the XorName.
    #[napi]
    pub fn xorname(&self) -> JsXorName {
        JsXorName(*self.0.xorname())
    }

    /// Returns the hex string representation of the address.
    #[napi]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Creates a new ChunkAddress from a hex string.
    #[napi(factory)]
    pub fn try_from_hex(hex: String) -> Result<Self> {
        let addr = ChunkAddress::try_from_hex(&hex).map_err(map_error)?;

        Ok(Self(addr))
    }
}

/// Address of a `GraphEntry`.
///
/// It is derived from the owner's unique public key
#[napi(js_name = "GraphEntryAddress")]
pub struct JsGraphEntryAddress(GraphEntryAddress);

#[napi]
impl JsGraphEntryAddress {
    /// Creates a new GraphEntryAddress.
    #[napi(constructor)]
    pub fn new(owner: &JsPublicKey) -> Self {
        Self(GraphEntryAddress::new(owner.0.clone()))
    }

    /// Return the network name of the scratchpad.
    /// This is used to locate the scratchpad on the network.
    #[napi]
    pub fn xorname(&self) -> JsXorName {
        JsXorName(self.0.xorname())
    }

    /// Serialize this `GraphEntryAddress` into a hex-encoded string.
    #[napi]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Parse a hex-encoded string into a `GraphEntryAddress`.
    #[napi(factory)]
    pub fn try_from_hex(hex: String) -> Result<Self> {
        let addr = GraphEntryAddress::from_hex(&hex).map_err(map_error)?;

        Ok(Self(addr))
    }
}

#[napi(js_name = "DataAddress")]
pub struct JsDataAddress(DataAddress);

#[napi(js_name = "ArchiveAddress")]
pub struct JsArchiveAddress(ArchiveAddress);

/// A wallet for interacting with the network's payment system
#[napi(js_name = "Wallet")]
pub struct JsWallet(Wallet);

#[napi]
impl JsWallet {
    /// Convenience function that creates a new Wallet with a random EthereumWallet.
    pub fn new_with_random_wallet(network: Network) -> Self {
        JsWallet(Wallet::new_with_random_wallet(network))
    }

    /// Creates a new Wallet based on the given Ethereum private key. It will fail with Error::PrivateKeyInvalid if private_key is invalid.
    #[napi(factory)]
    pub fn new_from_private_key(network: &JsNetwork, private_key: String) -> Result<Self> {
        let wallet =
            Wallet::new_from_private_key(network.0.clone(), &private_key).map_err(map_error)?;

        Ok(Self(wallet))
    }

    /// Returns a string representation of the wallet's address
    #[napi]
    pub fn address(&self) -> String {
        self.0.address().to_string()
    }

    /// Returns the `Network` of this wallet.
    pub fn network(&self) -> JsNetwork {
        JsNetwork(self.0.network().clone())
    }

    /// Returns the raw balance of payment tokens in the wallet
    #[napi]
    pub async fn balance(&self) -> Result<String> {
        let balance = self.0.balance_of_tokens().await.map_err(map_error)?;

        Ok(balance.to_string())
    }

    /// Returns the current balance of gas tokens in the wallet
    #[napi]
    pub async fn balance_of_gas(&self) -> Result<String> {
        let balance = self.0.balance_of_gas_tokens().await.map_err(map_error)?;

        Ok(balance.to_string())
    }
}

/// Options for making payments on the network
#[napi(js_name = "PaymentOption")]
pub struct JsPaymentOption(PaymentOption);

#[napi]
impl JsPaymentOption {
    #[napi(factory)]
    pub fn from_wallet(wallet: &JsWallet) -> Self {
        Self(PaymentOption::from(&wallet.0))
    }

    #[napi(factory)]
    pub fn from_receipt() -> Self {
        unimplemented!()
    }
}

#[napi(js_name = "Network")]
pub struct JsNetwork(Network);

#[napi]
impl JsNetwork {
    #[napi(constructor)]
    pub fn new(local: bool) -> Result<Self> {
        let network = Network::new(local).map_err(map_error)?;
        Ok(Self(network))
    }
}

#[napi(js_name = "PublicKey")]
pub struct JsPublicKey(PublicKey);

#[napi(js_name = "SecretKey")]
pub struct JsSecretKey(SecretKey);

#[napi(js_name = "GraphEntry")]
pub struct JsGPointerAddress(PointerAddress);

#[napi(js_name = "GraphEntry")]
pub struct JsGraphEntry(GraphEntry);

#[napi(js_name = "Pointer")]
pub struct JsPointer(Pointer);

#[napi(js_name = "PointerTarget")]
pub struct JsPointerTarget(PointerTarget);

#[napi(js_name = "PointerAddress")]
pub struct JsPointerAddress(PointerAddress);

#[napi(js_name = "Scratchpad")]
pub struct JsScratchpad(Scratchpad);

#[napi(js_name = "ScratchpadAddress")]
pub struct JsScratchpadAddress(ScratchpadAddress);

#[napi(js_name = "DataMapChunk")]
pub struct JsDataMapChunk(DataMapChunk);

#[napi(js_name = "PrivateArchiveDataMap")]
pub struct JsPrivateArchiveDataMap(PrivateArchiveDataMap);

#[napi(js_name = "PrivateArchive")]
pub struct JsPrivateArchive(PrivateArchive);

#[napi(js_name = "VaultSecretKey")]
pub struct JsVaultSecretKey(VaultSecretKey);

#[napi(js_name = "UserData")]
pub struct JsUserData(UserData);

#[napi(js_name = "VaultContentType")]
pub struct JsVaultContentType(VaultContentType);

#[napi(js_name = "RegisterAddress")]
pub struct JsRegisterAddress(RegisterAddress);

#[napi(js_name = "RegisterHistory")]
pub struct JsRegisterHistory(RegisterHistory);

#[napi(js_name = "PublicArchive")]
pub struct JsPublicArchive(PublicArchive);

#[napi(js_name = "RegisterValue")]
pub struct JsRegisterValue(RegisterValue);
