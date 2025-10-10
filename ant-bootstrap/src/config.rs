// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::error::{Error, Result};
use clap::Args;
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

/// The duration since last)seen before removing the address of a Peer.
const ADDR_EXPIRY_DURATION: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

/// Maximum peers to store
const MAX_PEERS: usize = 1500;

/// Maximum number of addresses to store for a Peer
const MAX_ADDRS_PER_PEER: usize = 3;

// Min time until we save the bootstrap cache to disk. 30 secs
const MIN_BOOTSTRAP_CACHE_SAVE_INTERVAL: Duration = Duration::from_secs(30);

// Max time until we save the bootstrap cache to disk. 3 hours
const MAX_BOOTSTRAP_CACHE_SAVE_INTERVAL: Duration = Duration::from_secs(3 * 60 * 60);

/// Configurations to fetch the initial peers which is used to bootstrap the network.
/// This could optionally also be used as a command line argument struct.
#[derive(Args, Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InitialPeersConfig {
    /// Set to indicate this is the first node in a new network
    ///
    /// If this argument is used, any others will be ignored because they do not apply to the first
    /// node.
    #[clap(long, default_value = "false")]
    pub first: bool,
    /// Addr(s) to use for bootstrap, in a 'multiaddr' format containing the peer ID.
    ///
    /// A multiaddr looks like
    /// '/ip4/1.2.3.4/tcp/1200/tcp/p2p/12D3KooWRi6wF7yxWLuPSNskXc6kQ5cJ6eaymeMbCRdTnMesPgFx' where
    /// `1.2.3.4` is the IP, `1200` is the port and the (optional) last part is the peer ID.
    ///
    /// This argument can be provided multiple times to connect to multiple peers.
    ///
    /// Alternatively, the `ANT_PEERS` environment variable can provide a comma-separated peer
    /// list.
    #[clap(
        long = "peer",
        value_name = "multiaddr",
        value_delimiter = ',',
        conflicts_with = "first"
    )]
    pub addrs: Vec<Multiaddr>,
    /// Specify the URL to fetch the network contacts from.
    ///
    /// The URL can point to a text file containing Multiaddresses separated by newline character, or
    /// a bootstrap cache JSON file.
    #[clap(long, conflicts_with = "first", value_delimiter = ',')]
    pub network_contacts_url: Vec<String>,
    /// Set to indicate this is a local network.
    #[clap(long, conflicts_with = "network_contacts_url", default_value = "false")]
    pub local: bool,
    /// Set to not load the bootstrap addresses from the local cache.
    #[clap(long, default_value = "false")]
    pub ignore_cache: bool,
    /// The directory to load and store the bootstrap cache. If not provided, the default path will be used.
    ///
    /// The JSON filename will be derived automatically from the network ID
    ///
    /// The default location is platform specific:
    ///  - Linux: $HOME/.local/share/autonomi/bootstrap_cache/bootstrap_cache_<network_id>.json
    ///  - macOS: $HOME/Library/Application Support/autonomi/bootstrap_cache/bootstrap_cache_<network_id>.json
    ///  - Windows: C:\Users\<username>\AppData\Roaming\autonomi\bootstrap_cache\bootstrap_cache_<network_id>.json
    #[clap(long)]
    pub bootstrap_cache_dir: Option<PathBuf>,
}

/// Configuration for the bootstrap cache
#[derive(Clone, Debug)]
pub struct BootstrapCacheConfig {
    /// The duration since last)seen before removing the address of a Peer.
    pub addr_expiry_duration: Duration,
    /// Enable backwards compatibility while writing the cache file.
    /// This will write the cache file in all versions of the cache file format.
    pub backwards_compatible_writes: bool,
    /// The directory to load and store the bootstrap cache. If not provided, the default path will be used.
    pub cache_dir: PathBuf,
    /// The cache save scaling factor. We start with the min_cache_save_duration and scale it up to the max_cache_save_duration.
    pub cache_save_scaling_factor: u32,
    /// Flag to disable writing to the cache file
    pub disable_cache_writing: bool,
    /// If set to true, the cache filename will be suffixed with "_local"
    pub local: bool,
    /// The max time duration until we save the bootstrap cache to disk.
    pub max_cache_save_duration: Duration,
    /// Maximum number of peers to keep in the cache
    pub max_peers: usize,
    /// Maximum number of addresses stored per peer.
    pub max_addrs_per_peer: usize,
    /// The min time duration until we save the bootstrap cache to disk.
    pub min_cache_save_duration: Duration,
}

impl TryFrom<&InitialPeersConfig> for BootstrapCacheConfig {
    type Error = Error;
    fn try_from(config: &InitialPeersConfig) -> Result<Self> {
        let mut bootstrap_config = BootstrapCacheConfig::empty();
        bootstrap_config.local = config.local;
        let cache_dir = if let Some(cache_dir) = &config.bootstrap_cache_dir {
            cache_dir.clone()
        } else {
            default_cache_dir()?
        };
        bootstrap_config.cache_dir = cache_dir;
        Ok(bootstrap_config)
    }
}

impl BootstrapCacheConfig {
    /// Creates a new BootstrapConfig with default settings
    pub fn new(local: bool) -> Result<Self> {
        Ok(Self {
            local,
            cache_dir: default_cache_dir()?,
            ..Self::empty()
        })
    }

    /// Creates a new BootstrapConfig with empty settings
    pub fn empty() -> Self {
        Self {
            addr_expiry_duration: ADDR_EXPIRY_DURATION,
            backwards_compatible_writes: false,
            max_peers: MAX_PEERS,
            max_addrs_per_peer: MAX_ADDRS_PER_PEER,
            cache_dir: PathBuf::new(),
            disable_cache_writing: false,
            local: false,
            min_cache_save_duration: MIN_BOOTSTRAP_CACHE_SAVE_INTERVAL,
            max_cache_save_duration: MAX_BOOTSTRAP_CACHE_SAVE_INTERVAL,
            cache_save_scaling_factor: 2,
        }
    }

    /// Set backwards compatible writes
    pub fn with_backwards_compatible_writes(mut self, enable: bool) -> Self {
        self.backwards_compatible_writes = enable;
        self
    }

    /// Set the local flag
    pub fn with_local(mut self, enable: bool) -> Self {
        self.local = enable;
        self
    }

    /// Set a new addr expiry duration
    pub fn with_addr_expiry_duration(mut self, duration: Duration) -> Self {
        self.addr_expiry_duration = duration;
        self
    }

    /// Update the config with a custom cache file path
    pub fn with_cache_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.cache_dir = path.as_ref().to_path_buf();
        self
    }

    /// Sets the maximum number of peers
    pub fn with_max_peers(mut self, max_peers: usize) -> Self {
        self.max_peers = max_peers;
        self
    }

    /// Sets the maximum number of addresses for a single peer.
    pub fn with_addrs_per_peer(mut self, max_addrs: usize) -> Self {
        self.max_addrs_per_peer = max_addrs;
        self
    }

    /// Sets the flag to disable writing to the cache file
    pub fn with_disable_cache_writing(mut self, disable: bool) -> Self {
        self.disable_cache_writing = disable;
        self
    }
}

/// Returns the default dir that should contain the bootstrap cache file
fn default_cache_dir() -> Result<PathBuf> {
    let dir = dirs_next::data_dir()
        .ok_or_else(|| Error::CouldNotObtainDataDir)
        .inspect_err(|err| {
            error!("Failed to obtain data directory: {err}");
        })?
        .join("autonomi")
        .join("bootstrap_cache");

    std::fs::create_dir_all(&dir).inspect_err(|err| {
        error!("Failed to create bootstrap cache directory at {dir:?}: {err}");
    })?;

    Ok(dir)
}
