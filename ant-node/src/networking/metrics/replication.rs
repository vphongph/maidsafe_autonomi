// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::EncodeLabelValue;
use std::collections::VecDeque;

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct ReplicateCandidateLabels {
    pub(crate) range: Range,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(crate) enum Range {
    WithinResponsibleDistance,
    OutsideResponsibleDistance,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct ReplicationSenderRangeLabels {
    pub(crate) within_closest_group: bool,
    pub(crate) within_extended_distance_range: bool,
    pub(crate) network_load: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct ReplicationSenderOutcomeLabels {
    pub(crate) outcome: ReplicationSenderOutcome,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(crate) enum ReplicationSenderOutcome {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct IncomingKeysMetricLabels {
    pub(crate) metric_type: IncomingMetricType,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelValue)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum IncomingMetricType {
    NewKeysPercent,
    LocallyStoredKeysPercent,
    FetchInProgressKeysPercent,
    OutOfRangeKeysPercent,
}

const STATS_WINDOW_SIZE: usize = 50;

/// Entry for tracking replication key statistics
#[derive(Debug, Clone, Default)]
pub(crate) struct ReplicationStatsEntry {
    pub(crate) total_keys: usize,
    pub(crate) new_keys: usize,
    pub(crate) locally_stored_keys: usize,
    pub(crate) fetch_in_progress_keys: usize,
    pub(crate) out_of_range_keys: usize,
}

/// Sliding window for tracking replication statistics
pub(crate) struct ReplicationStatsWindow {
    window: VecDeque<ReplicationStatsEntry>,
}

impl ReplicationStatsWindow {
    pub(crate) fn new() -> Self {
        Self {
            window: VecDeque::with_capacity(STATS_WINDOW_SIZE),
        }
    }

    /// Add a new entry to the sliding window
    pub(crate) fn add_entry(&mut self, entry: ReplicationStatsEntry) {
        if self.window.len() >= STATS_WINDOW_SIZE {
            let _ = self.window.pop_front();
        }
        self.window.push_back(entry);
    }

    /// Calculate the percentage of new keys across the window
    pub(crate) fn calculate_new_keys_percent(&self) -> f64 {
        self.calculate_percent(|entry| entry.new_keys)
    }

    /// Calculate the percentage of locally stored keys across the window
    pub(crate) fn calculate_locally_stored_keys_percent(&self) -> f64 {
        self.calculate_percent(|entry| entry.locally_stored_keys)
    }

    /// Calculate the percentage of fetch in progress keys across the window
    pub(crate) fn calculate_fetch_in_progress_keys_percent(&self) -> f64 {
        self.calculate_percent(|entry| entry.fetch_in_progress_keys)
    }

    /// Calculate the percentage of out-of-range keys across the window
    pub(crate) fn calculate_out_of_range_percent(&self) -> f64 {
        self.calculate_percent(|entry| entry.out_of_range_keys)
    }

    fn calculate_percent<F>(&self, field_selector: F) -> f64
    where
        F: Fn(&ReplicationStatsEntry) -> usize,
    {
        if self.window.is_empty() {
            return 0.0;
        }

        let (total_keys, selected_total) =
            self.window
                .iter()
                .fold((0usize, 0usize), |(acc_total, acc_selected), entry| {
                    (
                        acc_total + entry.total_keys,
                        acc_selected + field_selector(entry),
                    )
                });

        if total_keys == 0 {
            return 0.0;
        }

        (selected_total as f64 / total_keys as f64) * 100.0
    }
}
