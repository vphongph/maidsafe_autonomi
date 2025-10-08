// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ANT_PEERS_ENV;
use crate::BootstrapCacheConfig;
use crate::BootstrapCacheStore;
use crate::ContactsFetcher;
use crate::InitialPeersConfig;
use crate::Result;
use crate::contacts::ALPHANET_CONTACTS;
use crate::contacts::MAINNET_CONTACTS;
use crate::craft_valid_multiaddr;
use crate::craft_valid_multiaddr_from_str;
use crate::error::Error;
use ant_protocol::version::ALPHANET_ID;
use ant_protocol::version::MAINNET_ID;
use ant_protocol::version::get_network_id;
use libp2p::Multiaddr;
use std::collections::VecDeque;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use url::Url;

/// Manages the flow of obtaining bootstrap peer addresses from various sources:
/// 1. Environment variable `ANT_PEERS`
/// 2. Command-line provided addresses
/// 3. Bootstrap cache file on disk
/// 4. Network contacts endpoints
///
/// Addresses are returned one at a time via the `next_addr` method.
/// It handles asynchronous fetching from the cache and contacts endpoints,
/// ensuring only one fetch is in progress at a time.
///
/// If no more addresses are available from any source, `next_addr` returns an error.
/// It is expected that the caller will retry `next_addr` later to allow
/// for asynchronous fetches to complete.
pub struct Bootstrap {
    cache_store: BootstrapCacheStore,
    addrs: VecDeque<Multiaddr>,
    cache_pending: bool,
    contacts_progress: Option<ContactsProgress>,
    event_tx: UnboundedSender<FetchEvent>,
    event_rx: UnboundedReceiver<FetchEvent>,
    fetch_in_progress: Option<FetchKind>,
}

impl Bootstrap {
    pub async fn new(
        mut config: InitialPeersConfig,
        write_older_cache_files: bool,
    ) -> Result<Self> {
        let mut bootstrap_config = BootstrapCacheConfig::try_from(&config)?;
        bootstrap_config.backwards_compatible_writes = write_older_cache_files;

        let cache_store = BootstrapCacheStore::new(bootstrap_config)?;

        if config.first {
            info!("First node in network; clearing any existing cache");
            cache_store.write().await?;
        }

        let contacts_progress = Self::build_contacts_progress(&config)?;

        let mut addrs = VecDeque::new();
        if !config.first {
            for addr in Self::fetch_from_env() {
                addrs.push_back(addr);
            }

            for addr in config.addrs.drain(..) {
                if let Some(addr) = craft_valid_multiaddr(&addr, false) {
                    info!("Adding addr from arguments: {addr}");
                    addrs.push_back(addr);
                } else {
                    warn!("Invalid multiaddress format from arguments: {addr}");
                }
            }
        }

        let cache_pending = !config.first && !config.ignore_cache;
        if !cache_pending {
            info!("Not loading from cache as per configuration");
        }
        if !cache_pending && contacts_progress.is_none() && addrs.is_empty() {
            error!("No bootstrap peers configured from any source");
            return Err(Error::NoBootstrapPeersFound);
        }
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();

        Ok(Self {
            cache_store,
            addrs,
            cache_pending,
            contacts_progress,
            event_tx,
            event_rx,
            fetch_in_progress: None,
        })
    }

    /// Returns the next address to try for bootstrapping.
    /// None if a fetch is in progress and no address is ready yet.
    /// Error if there are no more addresses to try.
    pub fn next_addr(&mut self) -> Result<Option<Multiaddr>> {
        loop {
            self.process_events();

            if let Some(addr) = self.addrs.pop_front() {
                info!(?addr, "next_addr returning queued address");
                return Ok(Some(addr));
            }

            if self.fetch_in_progress.is_some() {
                info!("next_addr waiting for in-flight fetch result");
                return Ok(None);
            }

            if self.cache_pending && !matches!(self.fetch_in_progress, Some(FetchKind::Cache)) {
                info!("next_addr triggering cache fetch");
                self.start_cache_fetch()?;
                continue;
            }

            if self.contacts_progress.is_some()
                && !matches!(self.fetch_in_progress, Some(FetchKind::Contacts))
            {
                info!("next_addr triggering contacts fetch");
                self.start_contacts_fetch()?;
                if self.fetch_in_progress.is_some() {
                    return Ok(None);
                }
                continue;
            }

            info!("next_addr exhausted all address sources");
            return Err(Error::NoBootstrapPeersFound);
        }
    }

    fn process_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                FetchEvent::Cache(addrs) => {
                    info!(count = addrs.len(), "process_events received cache batch");
                    if addrs.is_empty() {
                        info!("No addresses retrieved from cache");
                    } else {
                        self.addrs.extend(addrs);
                    }
                }
                FetchEvent::Contacts(addrs) => {
                    info!(
                        count = addrs.len(),
                        "process_events received contacts batch"
                    );
                    if !addrs.is_empty() {
                        self.addrs.extend(addrs);
                    }
                    if self
                        .contacts_progress
                        .as_ref()
                        .is_none_or(ContactsProgress::is_empty)
                    {
                        self.contacts_progress = None;
                    }
                }
            }

            self.fetch_in_progress = None;
        }
    }

    fn start_cache_fetch(&mut self) -> Result<()> {
        if matches!(self.fetch_in_progress, Some(FetchKind::Cache)) {
            error!("Cache fetch already in progress, not starting another");
            return Ok(());
        }

        self.cache_pending = false;
        let config = self.cache_store.config().clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let addrs = match tokio::task::spawn_blocking(move || {
                BootstrapCacheStore::load_cache_data(&config)
            })
            .await
            {
                Ok(Ok(cache_data)) => cache_data.get_all_addrs().cloned().collect(),
                Ok(Err(err)) => {
                    warn!("Failed to load cache data: {err}");
                    Vec::new()
                }
                Err(err) => {
                    warn!("Cache fetch task failed to join: {err}");
                    Vec::new()
                }
            };

            info!(
                "Bootstrap cache loaded from disk with {} addresses",
                addrs.len()
            );
            let _ = event_tx.send(FetchEvent::Cache(addrs));
        });

        self.fetch_in_progress = Some(FetchKind::Cache);

        Ok(())
    }

    fn start_contacts_fetch(&mut self) -> Result<()> {
        if matches!(self.fetch_in_progress, Some(FetchKind::Contacts)) {
            error!("Contacts fetch already in progress, not starting another");
            return Ok(());
        }

        let Some(progress) = self.contacts_progress.as_mut() else {
            info!("No contacts progress available");
            return Ok(());
        };

        let Some(endpoint) = progress.next_endpoint() else {
            info!("No more contacts endpoints to try");
            self.contacts_progress = None;
            return Ok(());
        };

        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let Ok(fetcher) = ContactsFetcher::with_endpoints(vec![endpoint.clone()]) else {
                warn!("Failed to create contacts fetcher for {endpoint}");
                let _ = event_tx.send(FetchEvent::Contacts(Vec::new()));
                return;
            };

            let addrs = match fetcher.fetch_bootstrap_addresses().await {
                Ok(addrs) => addrs,
                Err(err) => {
                    warn!("Failed to fetch contacts from {endpoint}: {err}");
                    Vec::new()
                }
            };

            info!(
                "Contacts fetch completed from endpoint {endpoint:?} with {} addresses",
                addrs.len()
            );
            let _ = event_tx.send(FetchEvent::Contacts(addrs));
        });

        self.fetch_in_progress = Some(FetchKind::Contacts);

        Ok(())
    }

    fn build_contacts_progress(config: &InitialPeersConfig) -> Result<Option<ContactsProgress>> {
        if config.first {
            info!("First node in network; not fetching contacts");
            return Ok(None);
        }

        if config.local {
            info!("Local network configuration; skipping contacts endpoints");
            return Ok(None);
        }

        if !config.network_contacts_url.is_empty() {
            let endpoints = config
                .network_contacts_url
                .iter()
                .map(|endpoint| endpoint.parse::<Url>().map_err(|_| Error::FailedToParseUrl))
                .collect::<Result<Vec<_>>>()?;
            info!("Using provided contacts endpoints: {endpoints:?}");
            return Ok(ContactsProgress::new(endpoints));
        }

        match get_network_id() {
            id if id == MAINNET_ID => {
                info!("Using built-in mainnet contacts endpoints");
                Ok(ContactsProgress::from_static(MAINNET_CONTACTS))
            }

            id if id == ALPHANET_ID => {
                info!("Using built-in alphanet contacts endpoints");
                Ok(ContactsProgress::from_static(ALPHANET_CONTACTS))
            }
            _ => Ok(None),
        }
    }

    pub fn fetch_from_env() -> Vec<Multiaddr> {
        let mut bootstrap_addresses = Vec::new();
        // Read from ANT_PEERS environment variable if present
        if let Ok(addrs) = std::env::var(ANT_PEERS_ENV) {
            for addr_str in addrs.split(',') {
                if let Some(addr) = craft_valid_multiaddr_from_str(addr_str, false) {
                    info!("Adding addr from environment variable: {addr}");
                    bootstrap_addresses.push(addr);
                } else {
                    warn!("Invalid multiaddress format from environment variable: {addr_str}");
                }
            }
        }
        bootstrap_addresses
    }
}

struct ContactsProgress {
    remaining: VecDeque<Url>,
}

enum FetchEvent {
    Cache(Vec<Multiaddr>),
    Contacts(Vec<Multiaddr>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FetchKind {
    Cache,
    Contacts,
}

impl ContactsProgress {
    fn new(urls: Vec<Url>) -> Option<Self> {
        if urls.is_empty() {
            None
        } else {
            Some(Self {
                remaining: VecDeque::from(urls),
            })
        }
    }

    fn from_static(urls: &[&str]) -> Option<Self> {
        let mut parsed = Vec::new();
        for url in urls {
            match url.parse::<Url>() {
                Ok(parsed_url) => parsed.push(parsed_url),
                Err(err) => {
                    warn!("Failed to parse static contacts URL {url}: {err}");
                }
            }
        }
        Self::new(parsed)
    }

    fn next_endpoint(&mut self) -> Option<Url> {
        self.remaining.pop_front()
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        InitialPeersConfig,
        cache_store::{BootstrapCacheStore, cache_data_v1::CacheData},
        multiaddr_get_peer_id,
    };
    use libp2p::Multiaddr;
    use std::collections::HashSet;
    use std::sync::{Arc, OnceLock};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;
    use tokio::sync::{Mutex, OwnedMutexGuard};
    use tokio::time::sleep;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    async fn env_lock() -> OwnedMutexGuard<()> {
        static ENV_MUTEX: OnceLock<Arc<Mutex<()>>> = OnceLock::new();
        Arc::clone(ENV_MUTEX.get_or_init(|| Arc::new(Mutex::new(()))))
            .lock_owned()
            .await
    }

    #[allow(unsafe_code)]
    fn set_env_var(key: &str, value: &str) {
        unsafe {
            std::env::set_var(key, value);
        }
    }

    #[allow(unsafe_code)]
    fn remove_env_var(key: &str) {
        unsafe {
            std::env::remove_var(key);
        }
    }

    async fn expect_next_addr(flow: &mut Bootstrap) -> Result<Multiaddr> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match flow.next_addr() {
                Ok(Some(addr)) => return Ok(addr),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        panic!("Timed out waiting for next address");
                    }
                    sleep(Duration::from_millis(5)).await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn expect_err(flow: &mut Bootstrap) -> Error {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match flow.next_addr() {
                Ok(Some(addr)) => panic!("unexpected address returned: {addr}"),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        panic!("Timed out waiting for error from flow");
                    }
                    sleep(Duration::from_millis(5)).await;
                }
                Err(err) => return err,
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn returns_env_and_cli_addrs_before_other_sources() {
        let env_addr: Multiaddr =
            "/ip4/10.0.0.1/tcp/1200/p2p/12D3KooWQnE7zXkVUEGBnJtNfR88Ujz4ezgm6bVnkvxHCzhF7S5S"
                .parse()
                .unwrap();
        let cli_addr: Multiaddr =
            "/ip4/10.0.0.2/tcp/1201/p2p/12D3KooWQx2TSK7g1C8x3QK7gBqdqbQEkd6vDT7Pxu5gb1xmgjvp"
                .parse()
                .unwrap();

        let _env_guard = env_lock().await;
        set_env_var(ANT_PEERS_ENV, &env_addr.to_string());

        let mut flow = Bootstrap::new(
            InitialPeersConfig {
                addrs: vec![cli_addr.clone()],
                ignore_cache: true,
                local: true,
                ..Default::default()
            },
            false,
        )
        .await
        .unwrap();

        let got_env = expect_next_addr(&mut flow).await.unwrap();
        assert_eq!(got_env, env_addr);

        let got_cli = expect_next_addr(&mut flow).await.unwrap();
        assert_eq!(got_cli, cli_addr);

        let err = expect_err(&mut flow).await;
        assert!(matches!(err, Error::NoBootstrapPeersFound));

        remove_env_var(ANT_PEERS_ENV);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn loads_addresses_from_cache_when_initial_queue_is_empty() {
        let _env_guard = env_lock().await;
        remove_env_var(ANT_PEERS_ENV);
        let cache_addr: Multiaddr =
            "/ip4/127.0.0.1/tcp/1202/p2p/12D3KooWKGt8umjJQ4sDzFXo2UcHBaF33rqmFcWtXM6nbryL5G4J"
                .parse()
                .unwrap();
        let peer_id = multiaddr_get_peer_id(&cache_addr).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let file_name = BootstrapCacheStore::cache_file_name(true);

        let mut cache_data = CacheData::default();
        cache_data.add_peer(peer_id, std::iter::once(&cache_addr), 3, 10);
        cache_data
            .write_to_file(temp_dir.path(), &file_name)
            .unwrap();

        let mut flow = Bootstrap::new(
            InitialPeersConfig {
                local: true,
                bootstrap_cache_dir: Some(temp_dir.path().to_path_buf()),
                ..Default::default()
            },
            false,
        )
        .await
        .unwrap();

        let got = expect_next_addr(&mut flow).await.unwrap();
        assert_eq!(got, cache_addr);

        let err = expect_err(&mut flow).await;
        assert!(matches!(err, Error::NoBootstrapPeersFound));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn fetches_contacts_one_endpoint_at_a_time() {
        let _env_guard = env_lock().await;
        remove_env_var(ANT_PEERS_ENV);

        let mock_server = MockServer::start().await;

        let contact_one: Multiaddr =
            "/ip4/192.168.0.1/tcp/1203/p2p/12D3KooWPULWT1qXJ1jzYVtQocvKXgcv6U7Pp3ui3EB7mN8hXAsP"
                .parse()
                .unwrap();
        let contact_two: Multiaddr =
            "/ip4/192.168.0.2/tcp/1204/p2p/12D3KooWPsMPaEjaWjW6GWpAne6LYcwBQEJfnDbhQFNs6ytzmBn5"
                .parse()
                .unwrap();

        Mock::given(method("GET"))
            .and(path("/first"))
            .respond_with(ResponseTemplate::new(200).set_body_string(contact_one.to_string()))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/second"))
            .respond_with(ResponseTemplate::new(200).set_body_string(contact_two.to_string()))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut flow = Bootstrap::new(
            InitialPeersConfig {
                ignore_cache: true,
                network_contacts_url: vec![
                    format!("{}/first", mock_server.uri()),
                    format!("{}/second", mock_server.uri()),
                ],
                ..Default::default()
            },
            false,
        )
        .await
        .unwrap();

        let first = expect_next_addr(&mut flow).await.unwrap();
        assert_eq!(first, contact_one);

        let second = expect_next_addr(&mut flow).await.unwrap();
        assert_eq!(second, contact_two);

        let err = expect_err(&mut flow).await;
        assert!(matches!(err, Error::NoBootstrapPeersFound));

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].url.path(), "/first");
        assert_eq!(requests[1].url.path(), "/second");

        remove_env_var(ANT_PEERS_ENV);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn full_flow_traverses_all_sources_then_exhausts() {
        let _env_guard = env_lock().await;
        remove_env_var(ANT_PEERS_ENV);

        let env_addr: Multiaddr =
            "/ip4/10.1.0.1/tcp/1300/p2p/12D3KooWBbtXX6gY5xPD7NzNGGbj2428NJQ4HNvvBnSE5g4R7Pkf"
                .parse()
                .unwrap();
        let cli_addr: Multiaddr =
            "/ip4/10.1.0.2/tcp/1301/p2p/12D3KooWCRfYwq9c3PAXo5cTp3snq72Knqukcec4c9qT1AMyvMPd"
                .parse()
                .unwrap();
        set_env_var(ANT_PEERS_ENV, &env_addr.to_string());

        let cache_addr_one: Multiaddr =
            "/ip4/10.1.0.3/tcp/1302/p2p/12D3KooWMmKJcWUP9UqP4g1n3LH1htkvSUStn1aQGQxGc1dQcYxA"
                .parse()
                .unwrap();
        let cache_addr_two: Multiaddr =
            "/ip4/10.1.0.4/tcp/1303/p2p/12D3KooWA4b4T6Dz4RUtqnYDEBt3eGkqRykGGBqBP3ZiZsaAJ2jp"
                .parse()
                .unwrap();

        let temp_dir = TempDir::new().unwrap();
        let file_name = BootstrapCacheStore::cache_file_name(false);
        let mut cache_data = CacheData::default();
        cache_data.add_peer(
            multiaddr_get_peer_id(&cache_addr_one).unwrap(),
            std::iter::once(&cache_addr_one),
            3,
            10,
        );
        cache_data.add_peer(
            multiaddr_get_peer_id(&cache_addr_two).unwrap(),
            std::iter::once(&cache_addr_two),
            3,
            10,
        );
        cache_data
            .write_to_file(temp_dir.path(), &file_name)
            .unwrap();

        let mock_server = MockServer::start().await;
        let contact_one: Multiaddr =
            "/ip4/10.1.0.5/tcp/1304/p2p/12D3KooWQGyiCWkmKvgFVF1PsvBLnBxG29BAsoAhH4m6qjUpBAk1"
                .parse()
                .unwrap();
        let contact_two: Multiaddr =
            "/ip4/10.1.0.6/tcp/1305/p2p/12D3KooWGpMibW82dManEXZDV4SSQSSHqzTeWY5Avzkdx6yrosNG"
                .parse()
                .unwrap();

        Mock::given(method("GET"))
            .and(path("/contacts_one"))
            .respond_with(ResponseTemplate::new(200).set_body_string(contact_one.to_string()))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/contacts_two"))
            .respond_with(ResponseTemplate::new(200).set_body_string(contact_two.to_string()))
            .expect(1)
            .mount(&mock_server)
            .await;

        let file_path = temp_dir.path().join(format!(
            "version_{}/{}",
            CacheData::CACHE_DATA_VERSION,
            file_name
        ));
        let contents = std::fs::read_to_string(&file_path).unwrap();
        assert!(contents.contains(&cache_addr_one.to_string()));
        assert!(contents.contains(&cache_addr_two.to_string()));

        assert_eq!(
            Bootstrap::fetch_from_env(),
            vec![env_addr.clone()],
            "environment variable should yield the configured address"
        );

        let mut flow = Bootstrap::new(
            InitialPeersConfig {
                addrs: vec![cli_addr.clone()],
                bootstrap_cache_dir: Some(temp_dir.path().to_path_buf()),
                network_contacts_url: vec![
                    format!("{}/contacts_one", mock_server.uri()),
                    format!("{}/contacts_two", mock_server.uri()),
                ],
                ..Default::default()
            },
            false,
        )
        .await
        .unwrap();

        let initial_results = vec![
            expect_next_addr(&mut flow).await.unwrap(),
            expect_next_addr(&mut flow).await.unwrap(),
        ];
        let initial_set: HashSet<_> = initial_results.into_iter().collect();
        let expected_initial: HashSet<_> =
            [env_addr.clone(), cli_addr.clone()].into_iter().collect();
        assert_eq!(initial_set, expected_initial);

        let cache_results = vec![
            expect_next_addr(&mut flow).await.unwrap(),
            expect_next_addr(&mut flow).await.unwrap(),
        ];
        let cache_set: HashSet<_> = cache_results.into_iter().collect();
        let expected_cache: HashSet<_> = [cache_addr_one.clone(), cache_addr_two.clone()]
            .into_iter()
            .collect();
        assert_eq!(cache_set, expected_cache);

        let contact_first = expect_next_addr(&mut flow).await.unwrap();
        assert_eq!(contact_first, contact_one);

        let contact_second = expect_next_addr(&mut flow).await.unwrap();
        assert_eq!(contact_second, contact_two);

        let err = expect_err(&mut flow).await;
        assert!(matches!(err, Error::NoBootstrapPeersFound));

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].url.path(), "/contacts_one");
        assert_eq!(requests[1].url.path(), "/contacts_two");

        remove_env_var(ANT_PEERS_ENV);
    }
}
