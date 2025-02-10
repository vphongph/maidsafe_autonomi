// TODO: Shall be removed once the python binding warnings resolved
#![allow(non_local_definitions)]

use crate::{
    spawn::{
        network_spawner::{NetworkSpawner, RunningNetwork},
        node_spawner::NodeSpawner,
    },
    NodeBuilder, RunningNode,
};
use ant_evm::{EvmNetwork, RewardsAddress};
use ant_networking::{PutRecordCfg, ResponseQuorum};
use ant_protocol::{node::get_antnode_root_dir, storage::ChunkAddress, NetworkAddress};
use const_hex::FromHex;
use libp2p::{
    identity::{Keypair, PeerId},
    kad::Record as KadRecord,
    Multiaddr,
};
use pyo3::{exceptions::PyRuntimeError, exceptions::PyValueError, prelude::*, types::PyModule};
use pyo3_async_runtimes::tokio::future_into_py;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::Mutex;
use xor_name::XorName;

/// Python wrapper for the Autonomi Node
#[pyclass(name = "AntNode")]
pub struct PyAntNode {
    node: Arc<Mutex<RunningNode>>,
}

#[pymethods]
impl PyAntNode {
    /// Initialize and start a new node with the given configuration
    #[staticmethod]
    #[pyo3(signature = (
        rewards_address,
        evm_network,
        ip = "0.0.0.0",
        port = 0,
        initial_peers = vec![],
        local = false,
        root_dir = None,
        home_network = false,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn init<'p>(
        py: Python<'p>,
        rewards_address: String,
        evm_network: String,
        ip: &str,
        port: u16,
        initial_peers: Vec<String>,
        local: bool,
        root_dir: Option<String>,
        home_network: bool,
    ) -> PyResult<Bound<'p, PyAny>> {
        let rewards_address = RewardsAddress::from_hex(&rewards_address)
            .map_err(|e| PyValueError::new_err(format!("Invalid rewards address: {e}")))?;

        let evm_network = match evm_network.as_str() {
            "arbitrum_one" => EvmNetwork::ArbitrumOne,
            "arbitrum_sepolia" => EvmNetwork::ArbitrumSepolia,
            _ => {
                return Err(PyValueError::new_err(
                    "Invalid EVM network. Must be 'arbitrum_one' or 'arbitrum_sepolia'",
                ))
            }
        };

        let ip: IpAddr = ip
            .parse()
            .map_err(|e| PyValueError::new_err(format!("Invalid IP address: {e}")))?;

        let node_socket_addr = SocketAddr::new(ip, port);

        let initial_peers: Vec<Multiaddr> = initial_peers
            .into_iter()
            .map(|addr| addr.parse())
            .collect::<Result<_, _>>()
            .map_err(|e| PyValueError::new_err(format!("Invalid peer address: {e}")))?;

        let root_dir = root_dir.map(PathBuf::from);
        let keypair = Keypair::generate_ed25519();

        future_into_py(py, async move {
            let mut node_builder = NodeBuilder::new(
                keypair,
                rewards_address,
                evm_network,
                node_socket_addr,
                local,
                root_dir.unwrap_or_else(|| PathBuf::from(".")),
                false,
            );
            node_builder.initial_peers(initial_peers);
            node_builder.is_behind_home_network(home_network);

            let running_node = node_builder
                .build_and_run()
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to start node: {e}")))?;

            Ok(PyAntNode {
                node: Arc::new(Mutex::new(running_node)),
            })
        })
    }

    /// Get the node's PeerId as a string
    fn peer_id(self_: PyRef<Self>) -> PyResult<String> {
        let node_guard = self_
            .node
            .try_lock()
            .map_err(|_| PyRuntimeError::new_err("Failed to acquire node lock"))?;

        Ok(node_guard.peer_id().to_string())
    }

    /// Get all record addresses stored by the node
    fn get_all_record_addresses<'p>(
        self_: PyRef<'p, Self>,
        py: Python<'p>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let node = self_.node.clone();

        future_into_py(py, async move {
            let node_guard = node
                .try_lock()
                .map_err(|_| PyRuntimeError::new_err("Failed to acquire node lock"))?;

            let addresses = node_guard
                .get_all_record_addresses()
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to get addresses: {e}")))?;

            Ok(addresses
                .into_iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<_>>())
        })
    }

    /// Get the node's kbuckets information
    fn get_kbuckets<'p>(self_: PyRef<'p, Self>, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let node = self_.node.clone();

        future_into_py(py, async move {
            let node_guard = node
                .try_lock()
                .map_err(|_| PyRuntimeError::new_err("Failed to acquire node lock"))?;

            let kbuckets = node_guard
                .get_kbuckets()
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to get kbuckets: {e}")))?;

            Ok(Python::with_gil(|_py| {
                kbuckets
                    .into_iter()
                    .map(|(distance, peers)| {
                        (
                            distance,
                            peers.into_iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Vec<_>>()
            }))
        })
    }

    /// Get the node's rewards/wallet address as a hex string
    fn get_rewards_address(self_: PyRef<Self>) -> PyResult<String> {
        let node_guard = self_
            .node
            .try_lock()
            .map_err(|_| PyRuntimeError::new_err("Failed to acquire node lock"))?;

        Ok(format!("0x{}", hex::encode(node_guard.reward_address())))
    }

    /// Set a new rewards/wallet address for the node
    /// The address should be a hex string starting with "0x"
    fn set_rewards_address(self_: PyRef<Self>, address: String) -> PyResult<()> {
        let _node_guard = self_
            .node
            .try_lock()
            .map_err(|_| PyRuntimeError::new_err("Failed to acquire node lock"))?;

        // Remove "0x" prefix if present
        let address = address.strip_prefix("0x").unwrap_or(&address);

        // Validate the address format
        let _new_address = RewardsAddress::from_hex(address)
            .map_err(|e| PyValueError::new_err(format!("Invalid rewards address: {e}")))?;

        Err(PyRuntimeError::new_err(
            "Changing rewards address requires node restart. Please create a new node with the new address.",
        ))
    }

    /// Store a record in the node's storage
    fn store_record<'p>(
        self_: PyRef<'p, Self>,
        py: Python<'p>,
        key: String,
        value: Vec<u8>,
        _data_type: String,
    ) -> PyResult<Bound<'p, PyAny>> {
        let node = self_.node.clone();

        future_into_py(py, async move {
            let node_guard = node
                .try_lock()
                .map_err(|_| PyRuntimeError::new_err("Failed to acquire node lock"))?;

            let xorname = XorName::from_content(
                &hex::decode(key)
                    .map_err(|e| PyValueError::new_err(format!("Invalid key format: {e}")))?,
            );
            let chunk_address = ChunkAddress::new(xorname);
            let network_address = NetworkAddress::from_chunk_address(chunk_address);
            let record_key = network_address.to_record_key();

            let record = KadRecord {
                key: record_key,
                value,
                publisher: None,
                expires: None,
            };
            let cfg = PutRecordCfg {
                put_quorum: ResponseQuorum::One,
                retry_strategy: Default::default(),
                use_put_record_to: None,
                verification: None,
            };
            node_guard
                .network
                .put_record(record, &cfg)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to store record: {e}")))?;

            Ok(())
        })
    }

    /// Get a record from the node's storage
    fn get_record<'p>(
        self_: PyRef<'p, Self>,
        py: Python<'p>,
        key: String,
    ) -> PyResult<Bound<'p, PyAny>> {
        let node = self_.node.clone();

        future_into_py(py, async move {
            let node_guard = node
                .try_lock()
                .map_err(|_| PyRuntimeError::new_err("Failed to acquire node lock"))?;

            let xorname = XorName::from_content(
                &hex::decode(key)
                    .map_err(|e| PyValueError::new_err(format!("Invalid key format: {e}")))?,
            );
            let chunk_address = ChunkAddress::new(xorname);
            let network_address = NetworkAddress::from_chunk_address(chunk_address);
            let record_key = network_address.to_record_key();

            let record = node_guard
                .network
                .get_local_record(&record_key)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to get record: {e}")))?;

            Ok(record.map(|r| r.value.to_vec()))
        })
    }

    /// Delete a record from the node's storage
    fn delete_record<'p>(
        self_: PyRef<'p, Self>,
        py: Python<'p>,
        key: String,
    ) -> PyResult<Bound<'p, PyAny>> {
        let node = self_.node.clone();

        future_into_py(py, async move {
            let node_guard = node
                .try_lock()
                .map_err(|_| PyRuntimeError::new_err("Failed to acquire node lock"))?;

            let xorname = XorName::from_content(
                &hex::decode(key)
                    .map_err(|e| PyValueError::new_err(format!("Invalid key format: {e}")))?,
            );
            let chunk_address = ChunkAddress::new(xorname);
            let network_address = NetworkAddress::from_chunk_address(chunk_address);
            let record_key = network_address.to_record_key();

            // First check if we have the record using record_key
            let exists = node_guard
                .network
                .get_local_record(&record_key)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to get record: {e}")))?
                .is_some();

            Ok(Python::with_gil(|_py| exists))
        })
    }

    /// Get the total size of stored records
    fn get_stored_records_size<'p>(
        self_: PyRef<'p, Self>,
        py: Python<'p>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let node = self_.node.clone();

        future_into_py(py, async move {
            let node_guard = node
                .try_lock()
                .map_err(|_| PyRuntimeError::new_err("Failed to acquire node lock"))?;

            let records = node_guard
                .network
                .get_all_local_record_addresses()
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to get records: {e}")))?;

            let mut total_size = 0u64;
            for (key, _) in records {
                if let Ok(Some(record)) = node_guard
                    .network
                    .get_local_record(&key.to_record_key())
                    .await
                {
                    total_size += record.value.len() as u64;
                }
            }
            Ok(Python::with_gil(|_py| total_size))
        })
    }

    /// Get the current root directory path for node data
    fn get_root_dir(self_: PyRef<Self>) -> PyResult<String> {
        let node_guard = self_
            .node
            .try_lock()
            .map_err(|_| PyRuntimeError::new_err("Failed to acquire node lock"))?;

        Ok(node_guard
            .root_dir_path()
            .to_str()
            .ok_or_else(|| PyValueError::new_err("Invalid path encoding"))?
            .to_string())
    }

    /// Get the default root directory path for the given peer ID
    /// This is platform specific:
    ///  - Linux: $HOME/.local/share/autonomi/node/<peer-id>
    ///  - macOS: $HOME/Library/Application Support/autonomi/node/<peer-id>
    ///  - Windows: C:\Users\<username>\AppData\Roaming\autonomi\node\<peer-id>
    #[allow(clippy::redundant_closure)]
    #[staticmethod]
    #[pyo3(signature = (peer_id=None))]
    fn get_default_root_dir(peer_id: Option<String>) -> PyResult<String> {
        let peer_id = if let Some(id_str) = peer_id {
            let id = id_str
                .parse::<PeerId>()
                .map_err(|e| PyValueError::new_err(format!("Invalid peer ID: {e}")))?;
            Some(id)
        } else {
            None
        };

        let path = get_antnode_root_dir(peer_id.unwrap_or_else(|| PeerId::random()))
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to get default root dir: {e}")))?;

        Ok(path
            .to_str()
            .ok_or_else(|| PyValueError::new_err("Invalid path encoding"))?
            .to_string())
    }

    /// Get the logs directory path
    fn get_logs_dir(self_: PyRef<Self>) -> PyResult<String> {
        let node_guard = self_
            .node
            .try_lock()
            .map_err(|_| PyRuntimeError::new_err("Failed to acquire node lock"))?;

        let logs_path = node_guard.root_dir_path().join("logs");
        Ok(logs_path
            .to_str()
            .ok_or_else(|| PyValueError::new_err("Invalid path encoding"))?
            .to_string())
    }

    /// Get the data directory path where records are stored
    fn get_data_dir(self_: PyRef<Self>) -> PyResult<String> {
        let node_guard = self_
            .node
            .try_lock()
            .map_err(|_| PyRuntimeError::new_err("Failed to acquire node lock"))?;

        let data_path = node_guard.root_dir_path().join("data");
        Ok(data_path
            .to_str()
            .ok_or_else(|| PyValueError::new_err("Invalid path encoding"))?
            .to_string())
    }
}

#[pyclass(name = "RunningNetwork")]
pub struct PyRunningNetwork(Arc<Mutex<Option<RunningNetwork>>>);

#[pymethods]
impl PyRunningNetwork {
    fn bootstrap_peer<'a>(&mut self, py: Python<'a>) -> PyResult<Bound<'a, PyAny>> {
        let self_ = Arc::clone(&self.0);
        future_into_py(py, async move {
            let mut self_ = self_.lock().await;
            let running_network = self_.as_mut().ok_or_else(|| {
                PyRuntimeError::new_err("RunningNetwork probably already shutdown")
            })?;

            let peer = running_network.bootstrap_peer().await;

            Ok(peer.to_string())
        })
    }

    fn shutdown<'a>(&mut self, py: Python<'a>) -> PyResult<Bound<'a, PyAny>> {
        let self_ = Arc::clone(&self.0);
        future_into_py(py, async move {
            let mut self_ = self_.lock().await;
            let running_network = self_.take().ok_or_else(|| {
                PyRuntimeError::new_err("RunningNetwork probably already shutdown")
            })?;

            running_network.shutdown();

            Ok(())
        })
    }
}

#[pyclass(name = "NodeSpawner")]
pub struct PyNodeSpawner(Option<NodeSpawner>);

#[pymethods]
impl PyNodeSpawner {
    /// Create a new instance of `NodeSpawner` with default values.
    #[new]
    fn new() -> Self {
        Self(Some(NodeSpawner::new()))
    }

    /// Set the socket address for the node.
    pub fn with_socket_addr(&mut self, socket_addr: &str) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            let socket_addr = socket_addr
                .parse()
                .map_err(|e| PyValueError::new_err(format!("Invalid socket address: {e}")))?;
            self.0 = Some(self_.with_socket_addr(socket_addr));
        } else {
            return Err(PyRuntimeError::new_err("NodeSpawner inner error"));
        }
        Ok(())
    }

    /// Set the EVM network for the node to connect to.
    pub fn with_evm_network(&mut self, network: &str) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            let network = match network {
                "arbitrum_one" => EvmNetwork::ArbitrumOne,
                "arbitrum_sepolia" => EvmNetwork::ArbitrumSepolia,
                _ => {
                    return Err(PyValueError::new_err(
                        "Invalid EVM network. Must be 'arbitrum_one' or 'arbitrum_sepolia'",
                    ))
                }
            };
            self.0 = Some(self_.with_evm_network(network));
        } else {
            return Err(PyRuntimeError::new_err("NodeSpawner inner error"));
        }
        Ok(())
    }

    /// Set the rewards address for the node for distributing rewards.
    pub fn with_rewards_address(&mut self, rewards_address: &str) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            let rewards_address = rewards_address
                .parse()
                .map_err(|e| PyValueError::new_err(format!("Invalid rewards address: {e}")))?;
            self.0 = Some(self_.with_rewards_address(rewards_address));
        } else {
            return Err(PyRuntimeError::new_err("NodeSpawner inner error"));
        }
        Ok(())
    }

    /// Set the initial peers for the node.
    pub fn with_initial_peers(&mut self, initial_peers: Vec<String>) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            let initial_peers = initial_peers
                .into_iter()
                .map(|addr| addr.parse())
                .collect::<Result<_, _>>()
                .map_err(|e| PyValueError::new_err(format!("Invalid peer address: {e}")))?;
            self.0 = Some(self_.with_initial_peers(initial_peers));
        } else {
            return Err(PyRuntimeError::new_err("NodeSpawner inner error"));
        }
        Ok(())
    }

    /// Set the local mode flag for the node, indicating whether the node should run in local mode.
    pub fn with_local(&mut self, local: bool) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            self.0 = Some(self_.with_local(local));
        } else {
            return Err(PyRuntimeError::new_err("NodeSpawner inner error"));
        }
        Ok(())
    }

    /// Set the UPnP flag for the node.
    pub fn with_upnp(&mut self, upnp: bool) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            self.0 = Some(self_.with_upnp(upnp));
        } else {
            return Err(PyRuntimeError::new_err("NodeSpawner inner error"));
        }
        Ok(())
    }

    /// Set the root directory for the node.
    pub fn with_root_dir(&mut self, root_dir: PathBuf) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            self.0 = Some(self_.with_root_dir(Some(root_dir)));
        } else {
            return Err(PyRuntimeError::new_err("NodeSpawner inner error"));
        }

        Ok(())
    }

    /// Spawn the node using the configured parameters.
    pub fn spawn<'a>(&mut self, py: Python<'a>) -> PyResult<Bound<'a, PyAny>> {
        let self_ = self
            .0
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("NodeSpawner inner error"))?;

        future_into_py(py, async move {
            let running_node = self_
                .spawn()
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to spawn node: {e}")))?;

            Ok(PyAntNode {
                node: Arc::new(Mutex::new(running_node)),
            })
        })
    }
}

#[pyclass(name = "NetworkSpawner")]
pub struct PyNetworkSpawner(Option<NetworkSpawner>);

#[pymethods]
impl PyNetworkSpawner {
    /// Creates a new `NetworkSpawner` with default configurations.
    ///
    /// Default values:
    /// - `evm_network`: `EvmNetwork::default()`
    /// - `rewards_address`: `RewardsAddress::default()`
    /// - `local`: `false`
    /// - `upnp`: `false`
    /// - `root_dir`: `None`
    /// - `size`: `5`
    #[new]
    fn new() -> Self {
        Self(Some(NetworkSpawner::new()))
    }

    /// Set the EVM network for the network to use.
    pub fn with_evm_network(&mut self, network: &str) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            let network = match network {
                "arbitrum_one" => EvmNetwork::ArbitrumOne,
                "arbitrum_sepolia" => EvmNetwork::ArbitrumSepolia,
                _ => {
                    return Err(PyValueError::new_err(
                        "Invalid EVM network. Must be 'arbitrum_one' or 'arbitrum_sepolia'",
                    ))
                }
            };
            self.0 = Some(self_.with_evm_network(network));
        } else {
            return Err(PyRuntimeError::new_err("NetworkSpawner inner error"));
        }
        Ok(())
    }

    /// Set the rewards address for the nodes for distributing rewards.
    pub fn with_rewards_address(&mut self, rewards_address: &str) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            let rewards_address = rewards_address
                .parse()
                .map_err(|e| PyValueError::new_err(format!("Invalid rewards address: {e}")))?;
            self.0 = Some(self_.with_rewards_address(rewards_address));
        } else {
            return Err(PyRuntimeError::new_err("NetworkSpawner inner error"));
        }
        Ok(())
    }

    /// Set the local mode flag for the node, indicating whether the node should run in local mode.
    pub fn with_local(&mut self, local: bool) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            self.0 = Some(self_.with_local(local));
        } else {
            return Err(PyRuntimeError::new_err("NetworkSpawner inner error"));
        }
        Ok(())
    }

    /// Set the UPnP flag for the node.
    pub fn with_upnp(&mut self, upnp: bool) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            self.0 = Some(self_.with_upnp(upnp));
        } else {
            return Err(PyRuntimeError::new_err("NetworkSpawner inner error"));
        }
        Ok(())
    }

    /// Set the root directory for the node.
    pub fn with_root_dir(&mut self, root_dir: PathBuf) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            self.0 = Some(self_.with_root_dir(Some(root_dir)));
        } else {
            return Err(PyRuntimeError::new_err("NetworkSpawner inner error"));
        }

        Ok(())
    }

    /// Specifies the number of nodes to spawn in the network.
    pub fn with_size(&mut self, size: usize) -> PyResult<()> {
        if let Some(self_) = self.0.take() {
            self.0 = Some(self_.with_size(size));
        } else {
            return Err(PyRuntimeError::new_err("NetworkSpawner inner error"));
        }

        Ok(())
    }

    /// Spawns the network with the configured parameters.
    pub fn spawn<'a>(&mut self, py: Python<'a>) -> PyResult<Bound<'a, PyAny>> {
        let self_ = self
            .0
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("NetworkSpawner inner error"))?;

        future_into_py(py, async move {
            let running_network = self_
                .spawn()
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to spawn network: {e}")))?;

            Ok(PyRunningNetwork(Arc::new(Mutex::new(Some(
                running_network,
            )))))
        })
    }
}

/// Python module initialization
#[pymodule]
#[pyo3(name = "_antnode")]
fn init_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyAntNode>()?;
    m.add_class::<PyNodeSpawner>()?;
    m.add_class::<PyNetworkSpawner>()?;
    m.add_class::<PyRunningNetwork>()?;
    Ok(())
}
