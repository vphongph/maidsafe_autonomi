// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// Periodically check if the initial bootstrap process should be triggered.
/// This happens only once after the conditions for triggering the initial bootstrap process are met.
pub(crate) const INITIAL_BOOTSTRAP_CHECK_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(1);

/// This is used to track the conditions that are required to trigger the initial bootstrap process once.
pub(crate) struct InitialBootstrapTrigger {
    pub(crate) upnp: bool,
    pub(crate) upnp_gateway_result_obtained: bool,
    pub(crate) listen_addr_obtained: bool,
}

impl InitialBootstrapTrigger {
    pub(crate) fn new(upnp: bool) -> Self {
        Self {
            upnp,
            upnp_gateway_result_obtained: false,
            listen_addr_obtained: false,
        }
    }

    /// Used to check if we can trigger the initial bootstrap process.
    ///
    /// - If we are a client, we should trigger the initial bootstrap process immediately.
    /// - If we have set upnp flag and if we have obtained the upnp gateway result, we should trigger the initial bootstrap process.
    /// - If we don't have upnp enabled, then we should trigger the initial bootstrap process only if we have a listen address available.
    pub(crate) fn should_trigger_initial_bootstrap(&self) -> bool {
        if self.upnp {
            return self.upnp_gateway_result_obtained;
        }

        if self.listen_addr_obtained {
            return true;
        }

        false
    }
}
