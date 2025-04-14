// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::networking::utils::{is_a_relayed_peer, multiaddr_strip_p2p};
use crate::Multiaddr;
use ant_protocol::messages::{QueryResponse, Response};
use libp2p::identify::{Event, Info};
use libp2p::kad::{Event as KadEvent, ProgressStep, QueryId, QueryResult, QueryStats};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{Event as ReqEvent, Message, OutboundRequestId};
use libp2p::swarm::SwarmEvent;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum NetworkDriverError {
    #[error("TaskHandlerError: {0}")]
    TaskHandlerError(#[from] TaskHandlerError),
}

use super::task_handler::TaskHandlerError;
use super::{AutonomiClientBehaviourEvent, NetworkDriver};

impl NetworkDriver {
    /// Process a swarm event, ultimately handing over the event to the correct handler in [`crate::driver::task_handler::TaskHandler`]
    pub(crate) fn process_swarm_event(
        &mut self,
        swarm_event: SwarmEvent<AutonomiClientBehaviourEvent>,
    ) -> Result<(), NetworkDriverError> {
        match swarm_event {
            SwarmEvent::Behaviour(AutonomiClientBehaviourEvent::Identify(Event::Received {
                connection_id,
                peer_id,
                info,
            })) => {
                self.handle_identify_received(peer_id, info, connection_id);
                Ok(())
            }
            SwarmEvent::Behaviour(AutonomiClientBehaviourEvent::RequestResponse(
                ReqEvent::Message {
                    message:
                        Message::Response {
                            request_id,
                            response,
                        },
                    peer: _,
                    connection_id: _,
                },
            )) => self.handle_request_resp_event(request_id, response),
            SwarmEvent::Behaviour(AutonomiClientBehaviourEvent::Kademlia(
                KadEvent::OutboundQueryProgressed {
                    id,
                    result,
                    stats,
                    step,
                },
            )) => self.handle_kad_progress_event(id, result, &stats, &step),
            _other_event => {
                trace!("Other event: {:?}", _other_event);
                Ok(())
            }
        }
    }

    fn handle_identify_received(
        &mut self,
        peer_id: libp2p::PeerId,
        info: Info,
        connection_id: libp2p::swarm::ConnectionId,
    ) {
        debug!(conn_id=%connection_id, %peer_id, ?info, "identify: received info");

        if info.agent_version.contains("client") {
            debug!("Peer {peer_id:?} is a client. Not dialing or adding to RT.");
            return;
        }

        let mut addrs: HashSet<Multiaddr> = info
            .listen_addrs
            .into_iter()
            .map(|addr| multiaddr_strip_p2p(&addr))
            .collect();

        let is_relayed_peer = is_a_relayed_peer(addrs.iter());

        // Avoid have `direct link format` addrs co-exists with `relay` addr
        if is_relayed_peer {
            addrs.retain(|multiaddr| multiaddr.iter().any(|p| matches!(p, Protocol::P2pCircuit)));
        }

        debug!(%peer_id, ?addrs, "identify: attempting to add addresses to routing table");

        // Attempt to add the addresses to the routing table.
        for multiaddr in addrs {
            let _routing_update = self
                .swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer_id, multiaddr);
        }
    }

    fn handle_kad_progress_event(
        &mut self,
        id: QueryId,
        result: QueryResult,
        stats: &QueryStats,
        step: &ProgressStep,
    ) -> Result<(), NetworkDriverError> {
        // skip unknown or completed queries
        if !self.pending_tasks.contains(&id) {
            trace!("Ignore result for unknown query (possibly already completed): {id:?}");
            return Ok(());
        }

        // log info for queries we care about
        trace!(" | Kad progress event id: {:?}", id);
        trace!(" | stats: {:?}", stats);
        trace!(" | step: {:?}", step);

        match result {
            QueryResult::GetClosestPeers(res) => {
                trace!("GetClosestPeers: {:?}", res);
                self.pending_tasks.update_closest_peers(id, res)?;
            }
            QueryResult::GetRecord(res) => {
                trace!("GetRecord: {:?}", res);
                self.pending_tasks.update_get_record(id, res)?;
            }
            QueryResult::PutRecord(res) => {
                trace!("PutRecord: {:?}", res);
                self.pending_tasks.update_put_record(id, res)?;
            }
            QueryResult::GetProviders(res) => {
                trace!("GetProviders: {:?}", res);
            }
            QueryResult::Bootstrap(_) => {}
            QueryResult::StartProviding(_)
            | QueryResult::RepublishProvider(_)
            | QueryResult::RepublishRecord(_) => {}
        }
        Ok(())
    }

    fn handle_request_resp_event(
        &mut self,
        request_id: OutboundRequestId,
        response: Response,
    ) -> Result<(), NetworkDriverError> {
        trace!("Request response event: {:?}", response);

        // skip unknown or completed queries
        if !self.pending_tasks.contains_query(&request_id) {
            trace!("Ignore result for unknown query (possibly already completed): {request_id:?}");
            return Ok(());
        }

        if let Response::Query(QueryResponse::GetStoreQuote {
            quote,
            peer_address,
            storage_proofs: _,
        }) = response
        {
            self.pending_tasks
                .update_get_quote(request_id, quote, peer_address)?;
        }

        Ok(())
    }
}
