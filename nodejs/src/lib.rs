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
    /// Initialize the client with default configuration
    #[napi(factory)]
    pub async fn init() -> Result<Self> {
        let client = Client::init().await.map_err(map_error)?;

        Ok(Self(client))
    }

    /// Initialize a client that is configured to be local
    #[napi(factory)]
    pub async fn init_local() -> Result<Self> {
        let client = Client::init_local().await.map_err(map_error)?;

        Ok(Self(client))
    }

    /// Initialize a client that bootstraps from a list of peers
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

    /// Get a chunk from the network
    #[napi]
    pub async fn chunk_get(&self, addr: &JsChunkAddress) -> Result<Buffer> {
        let chunk = self.0.chunk_get(&addr.0).await.map_err(map_error)?;

        Ok(Buffer::from(chunk.value.to_vec()))
    }

    /// Manually upload a chunk to the network
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
