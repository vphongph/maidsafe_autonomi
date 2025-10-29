// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::commands::analyze::HolderStatus;

use super::ClosestPeerStatus;
use autonomi::client::analyze::{Analysis, AnalysisError};
use autonomi::networking::NetworkAddress;
use serde::Serialize;

/// Root JSON output structure
#[derive(Debug, Serialize)]
pub struct JsonOutput {
    pub provided_address: String,
    pub ant_package_version: String,
    pub analyzed_addresses: Vec<AnalyzedAddress>,
}

/// Analysis result for a single address
#[derive(Debug, Serialize)]
pub struct AnalyzedAddress {
    pub target_address: String,
    pub kad_method: KadMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closest_method: Option<ClosestMethod>,
}

/// Kademlia query result
#[derive(Debug, Serialize)]
pub struct KadMethod {
    pub query_status: KadQueryStatus,
    pub holding_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_type: Option<String>,
    pub holders: Vec<KadHolders>,
}

#[derive(Debug, Serialize)]
pub struct KadHolders {
    pub peer_id: String,
    pub distance_to_target_ilog2: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_size_bytes: Option<usize>,
}

/// Closest peers query result
#[derive(Debug, Serialize)]
pub struct ClosestMethod {
    pub closest_peers: Vec<ClosestPeer>,
    pub peer_count: usize,
}

/// Individual peer information
#[derive(Debug, Serialize)]
pub struct ClosestPeer {
    pub peer_id: String,
    pub holding_status: ClosestPeerHoldingStatus,
    pub distance_to_target_ilog2: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_size_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
}

/// Status of the kademlia query
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum KadQueryStatus {
    Success,
    Error,
}

/// Holding status for individual peers in closest peers query
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosestPeerHoldingStatus {
    Holding,
    NotHolding,
    FailedQuery,
}

impl JsonOutput {
    pub fn new(provided_address: String) -> Self {
        Self {
            provided_address,
            ant_package_version: env!("CARGO_PKG_VERSION").to_string(),
            analyzed_addresses: Vec::new(),
        }
    }

    pub fn add_address(&mut self, analyzed: AnalyzedAddress) {
        self.analyzed_addresses.push(analyzed);
    }
}

impl AnalyzedAddress {
    pub fn new(
        address: String,
        analysis_result: &Result<Analysis, AnalysisError>,
        closest_peers_data: Option<Vec<ClosestPeerStatus>>,
        holders: Option<Vec<HolderStatus>>,
        target_addr: &NetworkAddress,
    ) -> Self {
        let kad_method =
            KadMethod::from_analysis_and_holders(analysis_result, holders, target_addr);
        let closest_method =
            closest_peers_data.map(|peers| ClosestMethod::from_peer_statuses(peers, target_addr));
        Self {
            target_address: strip_0x_prefix(&address),
            kad_method,
            closest_method,
        }
    }
}

impl KadMethod {
    fn from_analysis_and_holders(
        analysis: &Result<Analysis, AnalysisError>,
        holders: Option<Vec<HolderStatus>>,
        target_addr: &NetworkAddress,
    ) -> Self {
        let kad_holders = if let Some(holders) = holders {
            holders
                .into_iter()
                .map(|holder| {
                    let peer_addr = NetworkAddress::from(holder.peer_id);
                    let distance = target_addr.distance(&peer_addr);
                    let distance_to_target_ilog2 = distance.ilog2().unwrap_or(0);
                    KadHolders {
                        peer_id: holder.peer_id.to_string(),
                        distance_to_target_ilog2,
                        record_size_bytes: Some(holder.size),
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        let query_status = if kad_holders.is_empty() && analysis.is_err() {
            KadQueryStatus::Error
        } else {
            KadQueryStatus::Success
        };

        let holding_count = if kad_holders.is_empty() {
            if analysis.is_ok() { 1 } else { 0 }
        } else {
            kad_holders.len() as u32
        };

        match analysis {
            Ok(analysis) => Self {
                query_status,
                holding_count,
                error_type: None,
                address_type: Some(get_analysis_type(analysis)),
                holders: kad_holders,
            },
            Err(err) => Self {
                query_status,
                holding_count,
                error_type: Some(map_analysis_error(err)),
                address_type: None,
                holders: kad_holders,
            },
        }
    }
}

impl ClosestMethod {
    fn from_peer_statuses(statuses: Vec<ClosestPeerStatus>, target_addr: &NetworkAddress) -> Self {
        let peer_count = statuses.len();
        let closest_peers = statuses
            .into_iter()
            .map(|status| ClosestPeer::from_status(status, target_addr))
            .collect();

        Self {
            closest_peers,
            peer_count,
        }
    }
}

impl ClosestPeer {
    fn from_status(status: ClosestPeerStatus, target_addr: &NetworkAddress) -> Self {
        let peer_id = status.peer_id().to_string();
        let peer_addr = NetworkAddress::from(*status.peer_id());
        let distance = target_addr.distance(&peer_addr);
        let distance_ilog2 = distance.ilog2().unwrap_or(0);

        match status {
            ClosestPeerStatus::Holding { size, .. } => Self {
                peer_id,
                holding_status: ClosestPeerHoldingStatus::Holding,
                distance_to_target_ilog2: distance_ilog2,
                record_size_bytes: Some(size),
                error_type: None,
            },
            ClosestPeerStatus::NotHolding { .. } => Self {
                peer_id,
                holding_status: ClosestPeerHoldingStatus::NotHolding,
                distance_to_target_ilog2: distance_ilog2,
                record_size_bytes: None,
                error_type: None,
            },
            ClosestPeerStatus::FailedQuery { error, .. } => Self {
                peer_id,
                holding_status: ClosestPeerHoldingStatus::FailedQuery,
                distance_to_target_ilog2: distance_ilog2,
                record_size_bytes: None,
                error_type: Some(error),
            },
        }
    }
}

/// Get the type name from Analysis enum
fn get_analysis_type(analysis: &Analysis) -> String {
    match analysis {
        Analysis::Chunk(_) => "Chunk".to_string(),
        Analysis::GraphEntry(_) => "GraphEntry".to_string(),
        Analysis::Pointer(_) => "Pointer".to_string(),
        Analysis::Scratchpad(_) => "Scratchpad".to_string(),
        Analysis::Register { .. } => "Register".to_string(),
        Analysis::DataMap { .. } => "DataMap".to_string(),
        Analysis::RawDataMap { .. } => "RawDataMap".to_string(),
        Analysis::PublicArchive { .. } => "PublicArchive".to_string(),
        Analysis::PrivateArchive(_) => "PrivateArchive".to_string(),
    }
}

/// Map AnalysisError to simple error type strings
fn map_analysis_error(error: &AnalysisError) -> String {
    match error {
        AnalysisError::UnrecognizedInput => "unrecognized_input".to_string(),
        AnalysisError::GetError(_) => "get_error".to_string(),
        AnalysisError::FailedGet => "failed_get".to_string(),
    }
}

/// Remove 0x prefix from hex strings if present
fn strip_0x_prefix(s: &str) -> String {
    s.trim_start_matches("0x").to_string()
}
