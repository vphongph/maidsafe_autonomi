use std::str::FromStr;

use autonomi::{
    client::payment::PaymentOption, AttoTokens, Bytes, Chunk, ChunkAddress, Client, Network,
    Wallet, XorName,
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
    ) -> Result<ChunkPutResult> {
        let chunk = Chunk::new(Bytes::from(data.as_ref().to_vec()));

        let (cost, addr) = self
            .0
            .chunk_put(&chunk, payment_option.0.clone())
            .await
            .map_err(map_error)?;

        Ok(ChunkPutResult { cost, addr })
    }

    /// Get the cost of a chunk.
    #[napi]
    pub async fn chunk_cost(&self, addr: &JsChunkAddress) -> Result</* AttoTokens */ String> {
        let cost = self.0.chunk_cost(&addr.0).await.map_err(map_error)?;

        Ok(cost.to_string())
    }

    // /// Upload chunks and retry failed uploads up to RETRY_ATTEMPTS times.
    // #[napi]
    // pub async fn upload_chunks_with_retries<'a>(
    //     &self,
    //     chunks: Vec<&'a Chunk>,
    //     receipt: &Receipt,
    // ) -> Vec<(&'a Chunk, PutError)> {
    //     todo!()
    // }

    // Graph entries

    /// Fetches a GraphEntry from the network.
    #[napi]
    pub async fn graph_entry_get(&self, address: &JsGraphEntryAddress) -> Result<JsGraphEntry> {
        todo!()
    }

    /// Check if a graph_entry exists on the network
    #[napi]
    pub async fn graph_entry_check_existance(&self, address: &JsGraphEntryAddress) -> Result<bool> {
        todo!()
    }

    /// Manually puts a GraphEntry to the network.
    #[napi]
    pub async fn graph_entry_put(
        &self,
        entry: &JsGraphEntry,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsGraphEntryAddress)> {
        todo!()
    }

    /// Get the cost to create a GraphEntry
    #[napi]
    pub async fn graph_entry_cost(&self, key: &JsPublicKey) -> Result</* AttoTokens */ String> {
        todo!()
    }

    // Pointers

    /// Get a pointer from the network
    #[napi]
    pub async fn pointer_get(&self, address: &JsPointerAddress) -> Result<JsPointer> {
        todo!()
    }

    /// Check if a pointer exists on the network
    #[napi]
    pub async fn pointer_check_existance(&self, address: &JsPointerAddress) -> Result<bool> {
        todo!()
    }

    /// Verify a pointer
    #[napi]
    pub fn pointer_verify(pointer: &JsPointer) -> Result<()> {
        todo!()
    }

    /// Manually store a pointer on the network
    #[napi]
    pub async fn pointer_put(
        &self,
        pointer: &JsPointer,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsPointerAddress)> {
        todo!()
    }

    /// Create a new pointer on the network.
    ///
    /// Make sure that the owner key is not already used for another pointer as each key is associated with one pointer
    #[napi]
    pub async fn pointer_create(
        &self,
        owner: &JsSecretKey,
        target: &JsPointerTarget,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsPointerAddress)> {
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
        owner: &JsSecretKey,
        target: &JsPointerTarget,
    ) -> Result<()> {
        todo!()
    }

    /// Calculate the cost of storing a pointer
    #[napi]
    pub async fn pointer_cost(&self, key: &JsPublicKey) -> Result</* AttoTokens */ String> {
        todo!()
    }

    // Scratchpad

    /// Get Scratchpad from the Network. A Scratchpad is stored at the owner's public key so we can derive the address from it.
    #[napi]
    pub async fn scratchpad_get_from_public_key(
        &self,
        public_key: &JsPublicKey,
    ) -> Result<JsScratchpad> {
        todo!()
    }

    /// Get Scratchpad from the Network
    #[napi]
    pub async fn scratchpad_get(&self, address: &JsScratchpadAddress) -> Result<JsScratchpad> {
        todo!()
    }

    /// Check if a scratchpad exists on the network
    #[napi]
    pub async fn scratchpad_check_existance(&self, address: &JsScratchpadAddress) -> Result<bool> {
        todo!()
    }

    /// Verify a scratchpad
    #[napi]
    pub fn scratchpad_verify(scratchpad: &JsScratchpad) -> Result<()> {
        todo!()
    }

    /// Manually store a scratchpad on the network
    #[napi]
    pub async fn scratchpad_put(
        &self,
        scratchpad: &JsScratchpad,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsScratchpadAddress)> {
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
        owner: &JsSecretKey,
        content_type: i64, // `u64`
        initial_data: Buffer,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsScratchpadAddress)> {
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
        owner: &JsSecretKey,
        content_type: i64, // `u64`
        data: Buffer,
    ) -> Result<()> {
        todo!()
    }

    /// Get the cost of creating a new Scratchpad
    #[napi]
    pub async fn scratchpad_cost(&self, owner: &JsPublicKey) -> Result</* AttoTokens */ String> {
        todo!()
    }

    // Data

    /// Fetch a blob of (private) data from the network
    #[napi]
    pub async fn data_get(&self, data_map: &JsDataMapChunk) -> Result<Buffer> {
        todo!()
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
    ) -> Result<(/* AttoTokens */ String, JsDataMapChunk)> {
        todo!()
    }

    /// Fetch a blob of data from the network
    #[napi]
    pub async fn data_get_public(&self, addr: &JsDataAddress) -> Result<Buffer> {
        todo!()
    }

    /// Upload a piece of data to the network. This data is publicly accessible.
    ///
    /// Returns the Data Address at which the data was stored.
    #[napi]
    pub async fn data_put_public(
        &self,
        data: Buffer,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, &JsDataAddress)> {
        todo!()
    }

    /// Get the estimated cost of storing a piece of data.
    #[napi]
    pub async fn data_cost(&self, data: Buffer) -> Result</* AttoTokens */ String> {
        todo!()
    }

    // Archives

    /// Fetch a PrivateArchive from the network
    #[napi]
    pub async fn archive_get(&self, addr: &JsPrivateArchiveDataMap) -> Result<JsPrivateArchive> {
        todo!()
    }

    /// Upload a PrivateArchive to the network
    #[napi]
    pub async fn archive_put(
        &self,
        archive: &JsPrivateArchive,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsPrivateArchiveDataMap)> {
        todo!()
    }

    // <TOPIC>

    /// Fetch an archive from the network
    #[napi]
    pub async fn archive_get_public(&self, addr: &JsArchiveAddress) -> Result<JsPublicArchive> {
        todo!()
    }

    /// Upload an archive to the network
    #[napi]
    pub async fn archive_put_public(
        &self,
        archive: &JsPublicArchive,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsArchiveAddress)> {
        todo!()
    }

    /// Get the cost to upload an archive
    #[napi]
    pub async fn archive_cost(&self, archive: &JsPublicArchive) -> Result</* AttoTokens */ String> {
        todo!()
    }

    // Files

    /// Download a private file from network to local file system
    #[napi]
    pub async fn file_download(
        &self,
        data_access: &JsDataMapChunk,
        to_dest: /* PathBuf */ String,
    ) -> Result<()> {
        todo!()
    }

    /// Download a private directory from network to local file system
    #[napi]
    pub async fn dir_download(
        &self,
        archive_access: &JsPrivateArchiveDataMap,
        to_dest: /* PathBuf */ String,
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
        dir_path: /* PathBuf */ String,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsPrivateArchive)> {
        todo!()
    }

    /// Same as Client::dir_content_upload but also uploads the archive (privately) to the network.
    ///
    /// Returns the PrivateArchiveDataMap allowing the private archive to be downloaded from the network.
    #[napi]
    pub async fn dir_upload(
        &self,
        dir_path: /* PathBuf */ String,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsPrivateArchiveDataMap)> {
        todo!()
    }

    /// Upload the content of a private file to the network. Reads file, splits into
    /// chunks, uploads chunks, uploads datamap, returns DataMapChunk (pointing to the datamap)
    #[napi]
    pub async fn file_content_upload(
        &self,
        path: /* PathBuf */ String,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsDataMapChunk)> {
        todo!()
    }

    /// Download file from network to local file system
    #[napi]
    pub async fn file_download_public(
        &self,
        data_addr: &JsDataAddress,
        to_dest: /* PathBuf */ String,
    ) -> Result<()> {
        todo!()
    }

    /// Download directory from network to local file system
    #[napi]
    pub async fn dir_download_public(
        &self,
        archive_addr: &JsArchiveAddress,
        to_dest: /* PathBuf */ String,
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
        dir_path: /* PathBuf */ String,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsPublicArchive)> {
        todo!()
    }

    /// Same as Client::dir_content_upload_public but also uploads the archive to the network.
    ///
    /// Returns the ArchiveAddress of the uploaded archive.
    #[napi]
    pub async fn dir_upload_public(
        &self,
        dir_path: /* PathBuf */ String,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsArchiveAddress)> {
        todo!()
    }

    /// Upload the content of a file to the network. Reads file, splits into chunks,
    /// uploads chunks, uploads datamap, returns DataAddr (pointing to the datamap)
    #[napi]
    pub async fn file_content_upload_public(
        &self,
        path: /* PathBuf */ String,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsDataAddress)> {
        todo!()
    }

    /// Get the cost to upload a file/dir to the network. quick and dirty implementation, please refactor once files are cleanly implemented
    #[napi]
    pub async fn file_cost(&self, path: /* &PathBuf */ String) -> Result</* AttoTokens */ String> {
        todo!()
    }

    // Vault/user data

    /// Get the user data from the vault
    #[napi]
    pub async fn get_user_data_from_vault(
        &self,
        secret_key: &JsVaultSecretKey,
    ) -> Result<JsUserData> {
        todo!()
    }

    /// Put the user data to the vault
    ///
    /// Returns the total cost of the put operation
    #[napi]
    pub async fn put_user_data_to_vault(
        &self,
        secret_key: &JsVaultSecretKey,
        payment_option: &JsPaymentOption,
        user_data: &JsUserData,
    ) -> Result</* AttoTokens */ String> {
        todo!()
    }

    /// Retrieves and returns a decrypted vault if one exists.
    ///
    /// Returns the content type of the bytes in the vault.
    #[napi]
    pub async fn fetch_and_decrypt_vault(
        &self,
        secret_key: &JsVaultSecretKey,
    ) -> Result<(Bytes, JsVaultContentType)> {
        todo!()
    }

    /// Get the cost of creating a new vault A quick estimation of cost:
    /// num_of_graph_entry * graph_entry_cost + num_of_scratchpad * scratchpad_cost
    #[napi]
    pub async fn vault_cost(
        &self,
        owner: &JsVaultSecretKey,
        max_size: /* u64 */ i64,
    ) -> Result</* AttoTokens */ String> {
        todo!()
    }

    /// Put data into the client’s VaultPacket
    ///
    /// Dynamically expand the vault capacity by paying for more space (Scratchpad) when needed.
    ///
    /// It is recommended to use the hash of the app name or unique identifier as the content type.

    #[napi]
    pub async fn write_bytes_to_vault(
        &self,
        data: Buffer,
        payment_option: &JsPaymentOption,
        secret_key: &JsVaultSecretKey,
        content_type: &JsVaultContentType,
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
    pub fn register_history(&self, addr: &JsRegisterAddress) -> JsRegisterHistory {
        todo!()
    }

    /// Create a new register key from a SecretKey and a name.
    ///
    /// This derives a new SecretKey from the owner’s SecretKey using the name. Note that you will need to keep track of the names you used to create the register key.
    #[napi]
    pub fn register_key_from_name(owner: &JsSecretKey, name: String) -> JsSecretKey {
        todo!()
    }

    /// Create a new RegisterValue from bytes, make sure the bytes are not longer than REGISTER_VALUE_SIZE
    #[napi]
    pub fn register_value_from_bytes(bytes: &[u8]) -> Result<JsRegisterValue> {
        todo!()
    }

    /// Create a new register with an initial value.
    ///
    /// Note that two payments are required, one for the underlying GraphEntry and one for the crate::Pointer
    #[napi]
    pub async fn register_create(
        &self,
        owner: &JsSecretKey,
        initial_value: &JsRegisterValue,
        payment_option: &JsPaymentOption,
    ) -> Result<(/* AttoTokens */ String, JsRegisterAddress)> {
        todo!()
    }

    /// Update the value of a register.
    ////
    /// The register needs to be created first with Client::register_create
    #[napi]
    pub async fn register_update(
        &self,
        owner: &JsSecretKey,
        new_value: &JsRegisterValue,
        payment_option: &JsPaymentOption,
    ) -> Result</* AttoTokens */ String> {
        todo!()
    }

    /// Get the current value of the register
    #[napi]
    pub async fn register_get(&self, addr: &JsRegisterAddress) -> Result<JsRegisterValue> {
        todo!()
    }

    /// Get the cost of a register operation. Returns the cost of creation if it doesn’t exist, else returns the cost of an update
    #[napi]
    pub async fn register_cost(&self, owner: &JsPublicKey) -> Result</* AttoTokens */ String> {
        todo!()
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

// This type exists because NAPI-RS does not support returning tuples.
#[napi]
pub struct ChunkPutResult {
    cost: AttoTokens,
    addr: ChunkAddress, // Can't be `JsChunkAddress` as NAPI-RS expects a reference in that case.
}
#[napi]
impl ChunkPutResult {
    #[napi(getter)]
    pub fn cost(&self) -> String {
        self.cost.to_string()
    }
    #[napi(getter)]
    pub fn addr(&self) -> JsChunkAddress {
        JsChunkAddress(self.addr.clone())
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
