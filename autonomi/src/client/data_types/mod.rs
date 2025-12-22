// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod chunk;
pub mod graph;
pub mod pointer;
pub mod scratchpad;

use crate::Client;
use crate::networking::{PeerId, Record};
use crate::utils::process_tasks_with_max_concurrency;
use ant_protocol::NetworkAddress;
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, warn};

/// Default number of closest peers to query in fallback fetch operations.
pub(crate) const FALLBACK_PEERS_COUNT: usize = 20;

impl Client {
    /// Fetches records from the closest peers directly in parallel.
    ///
    /// This function queries the closest N peers for a given key and returns all
    /// successfully retrieved records. This is useful as a fallback mechanism when
    /// standard DHT queries fail or for CRDT types that may have different versions
    /// on different nodes.
    ///
    /// # Arguments
    /// * `key` - The network address to query
    /// * `num_peers` - Maximum number of closest peers to query
    ///
    /// # Returns
    /// * `Some(Vec<Record>)` - All successfully retrieved records from the queried peers.
    ///   For CRDT types (Pointer, Scratchpad, GraphEntry), this may contain multiple
    ///   different record versions that need split resolution.
    /// * `None` - If no peers could be found or all peer queries failed.
    ///
    /// # Note
    /// The caller is responsible for:
    /// - For Chunk type: using the first valid record
    /// - For CRDT types (Pointer, Scratchpad, GraphEntry): returning the multiple copies for the further resolving
    pub(crate) async fn fetch_records_from_closest_peers(
        &self,
        key: NetworkAddress,
        num_peers: usize,
    ) -> Option<Vec<Record>> {
        debug!("Querying closest {num_peers} nodes directly for {key:?}");

        let closest_peers = match self
            .network
            .get_closest_peers(key.clone(), Some(num_peers))
            .await
        {
            Ok(peers) => peers,
            Err(e) => {
                error!("Failed to get closest peers for {key:?}: {e}");
                return None;
            }
        };

        debug!(
            "Querying {} closest peers in parallel for {key:?}",
            closest_peers.len()
        );

        // Create query tasks for all closest peers
        let mut query_tasks = vec![];
        for peer in closest_peers.iter() {
            let network = self.network.clone();
            let key = key.clone();
            let peer = peer.clone();
            query_tasks.push(async move { network.get_record_from_peer(key, peer).await });
        }

        // Process tasks with max concurrency of num_peers
        let results = process_tasks_with_max_concurrency(query_tasks, num_peers).await;

        // Collect all successful records
        let records: Vec<Record> = results
            .into_iter()
            .filter_map(|result| match result {
                Ok(Some(record)) => Some(record),
                _ => None,
            })
            .collect();

        if records.is_empty() {
            error!(
                "❌ All {} closest peers failed to return records for {key:?}",
                closest_peers.len()
            );
            None
        } else {
            debug!(
                "✅ Retrieved {} records from closest {num_peers} peers for {key:?}",
                records.len()
            );
            Some(records)
        }
    }
}

/// Resolve split records by selecting the highest counter.
/// If multiple records share the highest counter but have different content,
/// return a fork error constructed by the provided closure.
/// If deserialization fails for any record, return the deserialization error.
/// If no valid records remain, return a corrupt error constructed by the provided closure.
pub(crate) fn resolve_split_records<T, E, FDeser, FCounter, FEqual, FFork, FCorrupt>(
    result_map: HashMap<PeerId, Record>,
    key: NetworkAddress,
    deserialize: FDeser,
    counter_of: FCounter,
    same_content: FEqual,
    fork_error: FFork,
    corrupt_error: FCorrupt,
) -> Result<T, E>
where
    T: Clone + std::hash::Hash + Eq,
    FDeser: Fn(Record) -> Result<T, E>,
    FCounter: Fn(&T) -> u64,
    FEqual: Fn(&T, &T) -> bool,
    FFork: Fn(HashSet<T>) -> E,
    FCorrupt: Fn() -> E,
{
    debug!("Resolving split records at {key:?}");

    // Deserialize all records; if any fails, propagate the error upstream
    let mut items: Vec<T> = result_map
        .into_values()
        .map(deserialize)
        .collect::<Result<Vec<_>, _>>()?;

    if items.is_empty() {
        error!("Got empty records map for {key:?}");
        return Err(corrupt_error());
    }

    // Sort by counter then pick the max counter value
    items.sort_by_key(|t| counter_of(t));
    let max_counter = match items.last().map(&counter_of) {
        Some(c) => c,
        None => {
            error!("No records left after sorting for {key:?}");
            return Err(corrupt_error());
        }
    };

    // Collect unique entries with max counter
    let mut latest: HashSet<T> = HashSet::new();
    for item in items.into_iter() {
        if counter_of(&item) == max_counter
            && !latest.iter().any(|existing| same_content(existing, &item))
        {
            latest.insert(item);
        }
    }

    match latest.len() {
        1 => {
            let item = latest
                .into_iter()
                .next()
                .expect("HashSet with len() == 1 must contain exactly one item");
            Ok(item)
        }
        0 => {
            error!("No latest records found for {key:?}");
            Err(corrupt_error())
        }
        _ => {
            warn!("Multiple conflicting records found at latest version for {key:?}");
            Err(fork_error(latest))
        }
    }
}

/// Resolve records from a list of records (typically from fallback peer queries) for CRDT types.
///
/// This function requires at least `min_copies` consistent copies to consider the data valid.
/// It resolves conflicts by selecting the record with the highest counter, and if multiple
/// records share the highest counter, checks for consistency.
///
/// # Arguments
/// * `records` - List of records fetched from peers
/// * `key` - The network address (for logging)
/// * `deserialize` - Function to deserialize a record into type T
/// * `counter_of` - Function to extract the counter value from type T
/// * `same_content` - Function to compare if two items have the same content
/// * `fork_error` - Function to construct a fork error
/// * `corrupt_error` - Function to construct a corrupt error
///
/// # Returns
/// * `Ok(T)` - The resolved item with the highest counter and sufficient consistent copies
/// * `Err(E)` - If deserialization fails, data is corrupt, forked, or insufficient copies exist
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_records_from_peers<T, E, FDeser, FCounter, FEqual, FFork, FCorrupt>(
    records: Vec<Record>,
    key: NetworkAddress,
    deserialize: FDeser,
    counter_of: FCounter,
    same_content: FEqual,
    fork_error: FFork,
    corrupt_error: FCorrupt,
) -> Result<T, E>
where
    T: Clone + std::hash::Hash + Eq,
    FDeser: Fn(Record) -> Result<T, E>,
    FCounter: Fn(&T) -> u64,
    FEqual: Fn(&T, &T) -> bool,
    FFork: Fn(HashSet<T>) -> E,
    FCorrupt: Fn() -> E,
{
    debug!("Resolving {} records from peers for {key:?}", records.len());

    // Deserialize all records
    let mut items: Vec<T> = Vec::new();
    for record in records {
        match deserialize(record) {
            Ok(item) => items.push(item),
            Err(_) => {
                // Skip invalid records in fallback mode, we need to be resilient
                warn!("Skipping invalid record during fallback resolution at {key:?}");
            }
        }
    }

    if items.is_empty() {
        error!("No valid records found for {key:?}");
        return Err(corrupt_error());
    }

    // Sort by counter then pick the max counter value
    items.sort_by_key(|t| counter_of(t));
    let max_counter = match items.last().map(&counter_of) {
        Some(c) => c,
        None => {
            error!("No records left after sorting for {key:?}");
            return Err(corrupt_error());
        }
    };

    // Group items by content at the max counter
    let items_at_max: Vec<T> = items
        .into_iter()
        .filter(|item| counter_of(item) == max_counter)
        .collect();

    // Count consistent copies for each unique content
    let mut content_groups: Vec<(T, usize)> = Vec::new();
    for item in items_at_max.iter() {
        if let Some((_, count)) = content_groups
            .iter_mut()
            .find(|(existing, _)| same_content(existing, item))
        {
            *count += 1;
        } else {
            content_groups.push((item.clone(), 1));
        }
    }

    // Find the group(s) with the most copies
    let max_copies = content_groups.iter().map(|(_, c)| *c).max().unwrap_or(0);

    // Get all items with the max number of copies
    let best_items: HashSet<T> = content_groups
        .into_iter()
        .filter(|(_, count)| *count == max_copies)
        .map(|(item, _)| item)
        .collect();

    match best_items.len() {
        1 => {
            let item = best_items
                .into_iter()
                .next()
                .expect("HashSet with len() == 1 must contain exactly one item");
            debug!(
                "Successfully resolved {key:?} with {max_copies} consistent copies"
            );
            Ok(item)
        }
        0 => {
            error!("No valid content found for {key:?}");
            Err(corrupt_error())
        }
        _ => {
            warn!("Multiple conflicting records with equal copy counts for {key:?}");
            Err(fork_error(best_items))
        }
    }
}
