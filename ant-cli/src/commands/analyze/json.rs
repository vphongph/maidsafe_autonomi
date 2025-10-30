// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{AnalysisErrorDisplay, ClosestPeerStatus, NetworkErrorDisplay};
use crate::commands::analyze::{HolderStatus, KAD_HOLDERS_QUERY_RANGE};
use autonomi::client::analyze::{Analysis, AnalysisError};
use autonomi::networking::NetworkAddress;
use color_eyre::eyre::Result;
use file_rotate::{ContentLimit, FileRotate, compression::Compression, suffix::AppendCount};
use serde::Serialize;
use std::io::Write;
use std::path::Path;

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
    pub analysis_query: KadAnalysisQuery,
    pub holder_query: KadHolderQuery,
}

/// Kademlia analysis query result
#[derive(Debug, Serialize)]
pub struct KadAnalysisQuery {
    pub query_status: QueryStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<AnalysisErrorDisplay>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_type: Option<String>,
}

/// Kademlia holder query result
#[derive(Debug, Serialize)]
pub struct KadHolderQuery {
    pub query_range: u32,
    pub holding_count: u32,
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
    pub query_status: QueryStatus,
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
    pub error_type: Option<NetworkErrorDisplay>,
}

/// Status of the kademlia query
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub enum QueryStatus {
    Success,
    Error,
}

/// Holding status for individual peers in closest peers query
#[derive(Debug, Serialize)]
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
        let analysis_query = KadAnalysisQuery::from_analysis(analysis);
        let holder_query = KadHolderQuery::from_holders(holders, target_addr);

        Self {
            analysis_query,
            holder_query,
        }
    }
}

impl KadAnalysisQuery {
    fn from_analysis(analysis: &Result<Analysis, AnalysisError>) -> Self {
        match analysis {
            Ok(analysis) => Self {
                query_status: QueryStatus::Success,
                error_type: None,
                address_type: Some(get_analysis_type(analysis)),
            },
            Err(err) => Self {
                query_status: QueryStatus::Error,
                error_type: Some(AnalysisErrorDisplay::from_analysis_error(err)),
                address_type: None,
            },
        }
    }
}

impl KadHolderQuery {
    fn from_holders(holders: Option<Vec<HolderStatus>>, target_addr: &NetworkAddress) -> Self {
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

        Self {
            query_range: KAD_HOLDERS_QUERY_RANGE,
            holding_count: kad_holders.len() as u32,
            holders: kad_holders,
        }
    }
}

impl ClosestMethod {
    fn from_peer_statuses(statuses: Vec<ClosestPeerStatus>, target_addr: &NetworkAddress) -> Self {
        let peer_count = statuses.len();

        // Check if any peer has a failed query
        let has_failed_query = statuses
            .iter()
            .any(|status| matches!(status, ClosestPeerStatus::FailedQuery { .. }));

        // Determine query status: success if all peers are error-free (Holding or NotHolding)
        // failure if even one peer had a FailedQuery
        let query_status = if has_failed_query {
            QueryStatus::Error
        } else {
            QueryStatus::Success
        };

        let closest_peers = statuses
            .into_iter()
            .map(|status| ClosestPeer::from_status(status, target_addr))
            .collect();

        Self {
            query_status,
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

/// Remove 0x prefix from hex strings if present
fn strip_0x_prefix(s: &str) -> String {
    s.trim_start_matches("0x").to_string()
}

const MAX_FILE_SIZE: usize = 50 * 1024 * 1024; // 50 MB
const MAX_FILES: usize = 10;

/// Writer for JSON output that supports both file and directory targets
pub struct JsonWriter {
    writer: WriterType,
}

enum WriterType {
    /// Simple file writer (append-only)
    File(std::fs::File),
    /// Rotating file writer for directories
    Rotating(FileRotate<AppendCount>),
}

impl JsonWriter {
    /// Create a new JSON writer
    ///
    /// If path is a file, opens it in append mode.
    /// If path is a directory, creates a rotating file appender with:
    /// - 50 MB max per file
    /// - 10 files max
    /// - No compression
    pub fn new(path: &Path) -> Result<Self> {
        let writer = if path.is_dir() {
            // Directory: use rotating writer
            let json_file_path = path.join("analyze.json");
            let file_rotate = FileRotate::new(
                json_file_path,
                AppendCount::new(MAX_FILES),
                ContentLimit::BytesSurpassed(MAX_FILE_SIZE),
                Compression::None,
                #[cfg(unix)]
                None,
            );
            WriterType::Rotating(file_rotate)
        } else {
            // File: use simple append mode
            // Create parent directory if it doesn't exist
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            WriterType::File(file)
        };

        Ok(Self { writer })
    }

    /// Write JSON string to the output
    pub fn write_json(&mut self, json_str: &str) -> Result<()> {
        match &mut self.writer {
            WriterType::File(file) => {
                writeln!(file, "{json_str}")?;
                file.flush()?;
            }
            WriterType::Rotating(rotate) => {
                writeln!(rotate, "{json_str}")?;
                rotate.flush()?;
            }
        }
        Ok(())
    }
}
