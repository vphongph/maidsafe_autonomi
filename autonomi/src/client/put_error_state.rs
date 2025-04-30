// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::payment::Receipt;
use crate::networking::NetworkAddress;

#[derive(Debug, Clone, Default)]
pub struct PutErrorState {
    pub successful: Vec<NetworkAddress>,
    pub failed: Vec<NetworkAddress>,
    pub payment: Option<Receipt>,
}

impl PutErrorState {
    pub fn new(
        payment: Option<Receipt>,
        successful: Vec<NetworkAddress>,
        failed: Vec<NetworkAddress>,
    ) -> Self {
        Self {
            successful,
            failed,
            payment,
        }
    }

    pub fn one(payment: Option<Receipt>, address: NetworkAddress) -> Self {
        Self::new(payment, vec![address], vec![])
    }
}
