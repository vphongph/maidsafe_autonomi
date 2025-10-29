// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::actions::NetworkContext;
use autonomi::PublicKey;
use autonomi::chunk::ChunkAddress;
use autonomi::client::analyze::Analysis;
use autonomi::graph::GraphEntryAddress;
use autonomi::networking::PeerId;
use autonomi::{
    Multiaddr, RewardsAddress, SecretKey, Wallet, client::analyze::AnalysisError,
    networking::NetworkAddress,
};
use color_eyre::eyre::Result;
use futures::stream::{self, StreamExt};
use std::collections::HashMap;
use std::str::FromStr;

/// Status of a holder's record for a given address
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ClosestPeerStatus {
    /// Peer is holding the record with the given size in bytes
    Holding {
        peer_id: PeerId,
        target_address: NetworkAddress,
        listen_addrs: Vec<Multiaddr>,
        size: usize,
    },
    /// Peer is not holding the record
    NotHolding {
        peer_id: PeerId,
        target_address: NetworkAddress,
        listen_addrs: Vec<Multiaddr>,
    },
    /// Failed to query the peer
    FailedQuery {
        peer_id: PeerId,
        target_address: NetworkAddress,
        listen_addrs: Vec<Multiaddr>,
        error: String,
    },
}

impl ClosestPeerStatus {
    /// Get the listen addresses of the peer
    pub fn listen_addrs(&self) -> &Vec<Multiaddr> {
        match self {
            ClosestPeerStatus::Holding { listen_addrs, .. } => listen_addrs,
            ClosestPeerStatus::NotHolding { listen_addrs, .. } => listen_addrs,
            ClosestPeerStatus::FailedQuery { listen_addrs, .. } => listen_addrs,
        }
    }

    /// Get the peer ID
    pub fn peer_id(&self) -> &PeerId {
        match self {
            ClosestPeerStatus::Holding { peer_id, .. } => peer_id,
            ClosestPeerStatus::NotHolding { peer_id, .. } => peer_id,
            ClosestPeerStatus::FailedQuery { peer_id, .. } => peer_id,
        }
    }

    /// Get the target address
    #[allow(dead_code)]
    pub fn target_address(&self) -> &NetworkAddress {
        match self {
            ClosestPeerStatus::Holding { target_address, .. } => target_address,
            ClosestPeerStatus::NotHolding { target_address, .. } => target_address,
            ClosestPeerStatus::FailedQuery { target_address, .. } => target_address,
        }
    }
}

macro_rules! println_if {
    ($cond:expr, $($arg:tt)*) => {
        if $cond {
            println!($($arg)*);
        }
    };
}

pub async fn analyze(
    addr: &str,
    closest_nodes: bool,
    verbose: bool,
    network_context: NetworkContext,
    recursive: bool,
) -> Result<()> {
    println_if!(verbose, "Analyzing address: {addr}");

    // then connect to network and check data
    let client = crate::actions::connect_to_network(network_context)
        .await
        .map_err(|(err, _)| err)?;

    if closest_nodes {
        print_closest_nodes(&client, addr, verbose).await?;
    }

    let results = if recursive {
        println_if!(verbose, "Starting recursive analysis...");
        client.analyze_address_recursively(addr, verbose).await
    } else {
        let mut map = HashMap::new();
        let analysis = client.analyze_address(addr, verbose).await;
        map.insert(addr.to_string(), analysis);
        map
    };

    // Print results
    if recursive && results.len() > 1 {
        print_recursive_summary(&results);
    } else if let Some((_, analysis)) = results.iter().next() {
        match analysis {
            Ok(analysis) => {
                println_if!(verbose, "Analysis successful");
                println!("{analysis}");
            }
            Err(AnalysisError::UnrecognizedInput) => {
                println!("🚨 Could not identify address type!");
                println_if!(
                    verbose,
                    "Provided string was not recognized as a data address, trying other types..."
                );
                try_other_types(addr, verbose);
            }
            Err(e) => {
                println!("Analysis inconclusive: {e}");
            }
        }
    } else {
        println!("No analysis results available.");
    }

    Ok(())
}

fn try_other_types(addr: &str, verbose: bool) {
    // local reference to private data
    let try_private_address = crate::user_data::get_local_private_archive_access(addr).ok();
    if let Some(data_map) = try_private_address {
        println!(
            "✅ Identified input as a: Local Private Archive's DataMap local address (only works on your own machine)"
        );
        println_if!(
            verbose,
            "💡 This local address points to a DataMap which is stored on your local machine."
        );
        println_if!(
            verbose,
            "💡 Using this DataMap you can download your Private Archive from the Network."
        );
        println_if!(
            verbose,
            "💡 You can use the `file download` command to download the private data from the DataMap"
        );
        println!("DataMap in hex: {}", data_map.to_hex());
        return;
    }

    // cryptographic keys
    let hex_addr = addr.trim_start_matches("0x");
    let maybe_secret_key = SecretKey::from_hex(hex_addr).ok();
    let maybe_eth_sk = Wallet::new_from_private_key(Default::default(), hex_addr).ok();
    if maybe_secret_key.is_some() || maybe_eth_sk.is_some() {
        println!("🚨 Please keep your secret key safe! Don't use it as a data address!");
        println!("✅ Identified input as a: Secret Key");
        println_if!(
            verbose,
            "💡 A Secret Key is used to sign data or transactions on the Network."
        );
        return;
    }
    let maybe_eth_address = addr.parse::<RewardsAddress>().ok();
    if maybe_eth_address.is_some() {
        println!("✅ Identified input as an: Ethereum Address");
        println_if!(
            verbose,
            "💡 An Ethereum address is a cryptographic identifier for a blockchain account. It can be used to receive funds and rewards on the Network."
        );
        return;
    }

    // multiaddrs
    let maybe_multiaddr = Multiaddr::from_str(addr).ok();
    if maybe_multiaddr.is_some() {
        println!("✅ Identified input as a: Multiaddr");
        println_if!(
            verbose,
            "💡 A Mutliaddr is the url used to connect to a node on the Network."
        );
        return;
    }

    println!("⚠️ Unrecognized input");
}

/// Get holder status for the closest nodes to an address
///
/// Returns a map of PeerIds to their HolderStatus for the given address
pub async fn get_closest_nodes_status(
    client: &autonomi::Client,
    addr: &str,
    verbose: bool,
) -> Result<Vec<ClosestPeerStatus>> {
    let hex_addr = addr.trim_start_matches("0x");

    println_if!(verbose, "Querying closest peers to address...");

    // Try parsing as ChunkAddress (XorName) first
    let target_addr = if let Ok(chunk_addr) = ChunkAddress::from_hex(addr) {
        println_if!(verbose, "Identified as ChunkAddress");
        NetworkAddress::from(chunk_addr)
    // Try parsing as PublicKey (could be GraphEntry, Pointer, or Scratchpad)
    } else if let Ok(public_key) = PublicKey::from_hex(hex_addr) {
        println_if!(verbose, "Identified as PublicKey, using GraphEntryAddress");
        // Default to GraphEntryAddress for public keys
        NetworkAddress::from(GraphEntryAddress::new(public_key))
    } else {
        return Err(color_eyre::eyre::eyre!(
            "Could not parse address. Expected a hex-encoded ChunkAddress or PublicKey"
        ));
    };

    // Get closest group to the target addr
    let peers = client
        .get_closest_to_address(target_addr.clone(), Some(20))
        .await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to get closest peers: {e}"))?;

    println!("Found {} closest peers to {}:", peers.len(), addr);
    println!();

    // Query all peers concurrently
    let query_tasks = peers.iter().map(|peer| {
        let client = client.clone();
        let target_addr = target_addr.clone();
        let peer = peer.clone();
        async move {
            let status = match client
                .get_record_from_peer(target_addr.clone(), peer.clone())
                .await
            {
                Ok(Some(record)) => ClosestPeerStatus::Holding {
                    peer_id: peer.peer_id,
                    listen_addrs: peer.addrs.clone(),
                    target_address: target_addr.clone(),
                    size: record.value.len(),
                },
                Ok(None) => ClosestPeerStatus::NotHolding {
                    peer_id: peer.peer_id,
                    listen_addrs: peer.addrs.clone(),
                    target_address: target_addr.clone(),
                },
                Err(e) => ClosestPeerStatus::FailedQuery {
                    peer_id: peer.peer_id,
                    listen_addrs: peer.addrs.clone(),
                    target_address: target_addr.clone(),
                    error: e.to_string(),
                },
            };
            status
        }
    });

    let holders_map: Vec<ClosestPeerStatus> = stream::iter(query_tasks)
        .buffered(*autonomi::client::config::CHUNK_DOWNLOAD_BATCH_SIZE)
        .collect()
        .await;

    Ok(holders_map)
}

async fn print_closest_nodes(client: &autonomi::Client, addr: &str, verbose: bool) -> Result<()> {
    let hex_addr = addr.trim_start_matches("0x");

    // Try parsing as ChunkAddress (XorName) first
    let target_addr = if let Ok(chunk_addr) = ChunkAddress::from_hex(addr) {
        NetworkAddress::from(chunk_addr)
    // Try parsing as PublicKey (could be GraphEntry, Pointer, or Scratchpad)
    } else if let Ok(public_key) = PublicKey::from_hex(hex_addr) {
        // Default to GraphEntryAddress for public keys
        NetworkAddress::from(GraphEntryAddress::new(public_key))
    } else {
        return Err(color_eyre::eyre::eyre!(
            "Could not parse address. Expected a hex-encoded ChunkAddress or PublicKey"
        ));
    };

    // Get the holder status map
    let mut holders_map = get_closest_nodes_status(client, addr, verbose).await?;

    // Sort peers by distance to target address
    holders_map.sort_by_key(|status| {
        let peer_addr = NetworkAddress::from(*status.peer_id());
        target_addr.distance(&peer_addr)
    });

    // Print status for each peer
    for (i, status) in holders_map.iter().enumerate() {
        let peer_id = status.peer_id();
        let peer_addr = NetworkAddress::from(*peer_id);
        let distance = target_addr.distance(&peer_addr);

        println!(
            "{}. Peer ID: {peer_id} (distance: {distance:?}[{:?}])",
            i + 1,
            distance.ilog2()
        );

        // Print status from the map
        match status {
            ClosestPeerStatus::Holding { size, .. } => {
                println!("   Status: ✅ HOLDING record (size: {size} bytes)");
            }
            ClosestPeerStatus::NotHolding { .. } => {
                println!("   Status: ❌ NOT holding record");
            }
            ClosestPeerStatus::FailedQuery { error, .. } => {
                println!("   Status: ⚠️  Failed to query: {error}");
            }
        }

        if verbose {
            println!("   Addresses:");
            for addr in status.listen_addrs() {
                println!("     - {addr}");
            }
        }
        println!();
    }

    // Print 2-D distance matrix among sorted peers
    println!("\n{}", "=".repeat(80));
    println!("Distance Matrix Among Closest Peers:");
    println!("{}", "=".repeat(80));
    println!();

    // Print header row with peer indices
    print!("     ");
    for i in 0..holders_map.len() {
        print!("Peer {:2} ", i + 1);
    }
    println!();
    print!("     ");
    for _ in 0..holders_map.len() {
        print!("{} ", "-".repeat(7));
    }
    println!();

    // Print each row of the distance matrix
    for (i, status) in holders_map.iter().enumerate() {
        print!("P{:2}  ", i + 1);
        let addr_i = NetworkAddress::from(*status.peer_id());

        for peer_j in holders_map.iter() {
            let addr_j = NetworkAddress::from(*peer_j.peer_id());
            let distance = addr_i.distance(&addr_j);

            // Display distance with ilog2 for readability
            if addr_i == addr_j {
                print!("   -    ");
            } else {
                print!("{:?} ", distance.ilog2());
            }
        }
        println!();
    }

    Ok(())
}

fn print_recursive_summary(results: &HashMap<String, Result<Analysis, AnalysisError>>) {
    println!("\n{:<70} | {:<15} | Status", "Address", "Type");
    println!("{}", "─".repeat(98));

    for (address, result) in results {
        let (type_name, status) = match result {
            Ok(analysis) => {
                let type_str = match analysis {
                    Analysis::Chunk(_) => "Chunk",
                    Analysis::GraphEntry(_) => "GraphEntry",
                    Analysis::Pointer(_) => "Pointer",
                    Analysis::Scratchpad(_) => "Scratchpad",
                    Analysis::Register { .. } => "Register",
                    Analysis::DataMap { .. } => "DataMap",
                    Analysis::RawDataMap { .. } => "RawDataMap",
                    Analysis::PublicArchive { .. } => "PublicArchive",
                    Analysis::PrivateArchive(_) => "PrivateArchive",
                };
                (type_str, "✓ Found")
            }
            Err(_) => ("Unknown", "✗ Not found"),
        };

        println!("{address:<70} | {type_name:<15} | {status}");
    }

    println!("\nTotal: {} addresses", results.len());
}
