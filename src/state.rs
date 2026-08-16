// Copyright © 2024-26 The Johns Hopkins Applied Physics Laboratory LLC.
//
// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public License,
// version 3, as published by the Free Software Foundation.  If you
// would like to purchase a commercial license for this software, please
// contact APL’s Tech Transfer at 240-592-0817 or
// techtransfer@jhuapl.edu.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program.  If not, see
// <https://www.gnu.org/licenses/>.

//! Core protocol state implementations for the Castro-Liskov PBFT
//! consensus protocol.

use std::array::TryFromSliceError;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::marker::PhantomData;
use std::mem::replace;
use std::time::Duration;
use std::time::Instant;

use bitvec::prelude::BitVec;
use bitvec::prelude::bitvec;
use constellation_common::hashid::HashAlgo;
use constellation_common::hashid::HashID;
use constellation_consensus_common::oper::OperBatch;
use constellation_consensus_common::oper::OperBatches;
use constellation_consensus_common::outbound::Outbound;
use constellation_consensus_common::parties::Parties;
use constellation_consensus_common::parties::PartyRoundIDMap;
use constellation_consensus_common::parties::PartyTypes;
use constellation_consensus_common::parties::RoundPartyIDTypes;
use constellation_consensus_common::parties::RoundPartyIdxTypes;
use constellation_consensus_common::proto::ConsensusProtoMsgTypes;
use constellation_consensus_common::proto::ConsensusProtoOutboundTypes;
use constellation_consensus_common::state::ProtoState;
use constellation_consensus_common::state::ProtoStateRound;
use constellation_consensus_common::state::ProtoStateSetParties;
use constellation_consensus_common::state::ProtoStateSubmit;
use constellation_consensus_common::state::RoundState;
use constellation_consensus_common::state::RoundStateNotify;
use constellation_consensus_common::state::RoundStateRecv;
use constellation_consensus_common::state::RoundStateUpdate;
use log::debug;
use log::error;
use log::info;
use log::trace;
use log::warn;
use rand::random;

use crate::config::PBFTOutboundConfig;
use crate::config::PBFTProtoStateConfig;
use crate::generated::msgs::PbftContent;
use crate::generated::msgs::PbftMsg;
use crate::generated::msgs::PbftStateUpdate;
use crate::generated::msgs::PbftUpdateAck;
use crate::generated::req::PbftRequest;
use crate::generated::req::PbftView;
use crate::outbound::OutboundPartyIdx;
use crate::outbound::PBFTOutbound;
use crate::outbound::PBFTOutboundSend;

const SELF_PARTY: usize = 0;

#[derive(Clone, Default)]
pub struct PBFTProtoTypes;

/// Hints as to who to nominate for leader in a round.
#[derive(Clone)]
enum PBFTLeaderHint<Party> {
    /// Make some other party the leader.
    Other {
        /// The party to make leader.
        party: Party
    },
    /// Make ourselves the leader.
    This
}

/// Leader state.
#[derive(Clone)]
enum PBFTLeader<Party, Hint> {
    /// Someone else is the leader.
    Other {
        /// Number of failures consecutive failures..
        nconsecutive_failures: usize,
        /// Number of failures since last view change.
        nfailures: usize,
        /// Number of rounds since last view change.
        nrounds: usize,
        /// Time since requests became available.
        stall_start: Option<Instant>,
        /// Time since the last view change.
        view_start: Instant,
        /// The current leader.
        party: Party
    },
    /// No one is the leader.
    None {
        /// Hint as to who we should vote for.
        hint: Hint
    },
    /// We are the leader.
    This
}

/// Inter-round state for the Castro-Liskov PBFT consensus protocol.
pub struct PBFTProtoState<H, Party>
where
    H: Default + HashAlgo,
    H::HashID: Clone + Display + Eq + Hash,
    Party: Clone + Display + Eq + Hash {
    /// Configuration for creating [PBFTOutbound]s.
    outbound_config: PBFTOutboundConfig,
    /// Hash algorithm to use for parties
    hash: H,
    /// Map from other parties to hashes.
    party_hashes: HashMap<Party, H::HashID>,
    /// Map from hashes to other parties.
    hash_parties: HashMap<H::HashID, Party>,
    /// Current leader.
    leader: PBFTLeader<Party, Option<PBFTLeaderHint<Party>>>,
    /// Hash for this party.
    self_hash: H::HashID,
    /// Number of rounds before we start proposing view changes.
    view_change_rounds: usize,
    /// Number of consecutive failed rounds before we start proposing
    /// view changes.
    view_change_consecutive_failures: usize,
    /// Number of failed rounds before we start proposing view
    /// changes.
    view_change_failures: usize,
    /// Wall-clock time before we start proposing view changes.
    view_change_time: Option<Duration>,
    /// Wall-clock time without a successful round before we start
    /// proposing view changes.
    ///
    /// This will not trigger if there are no pending transactions.
    view_change_stall_time: Option<Duration>,
    /// Pending requests.
    pending: OperBatches<H::HashID>
}

/// State for preparation of a request.
///
/// This is slightly more complicated than an [Option], because we
/// need to store the deadline at which we can propose view changes in
/// the `None` variant.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PreparedReq<H, Req>
where
    H: HashID {
    /// We have already prepared a request.
    Prepared {
        /// The request we prepared.
        req: Req
    },
    /// No request has been prepared yet.
    None {
        /// Time at whcih view changes will be proposed.
        deadline: Option<Instant>,
        /// Who to vote for as leader if a view change is originated.
        leader_vote: H
    }
}

/// PBFT state for the "prepare" phase.
pub struct PrepareState<H, Req>
where
    Req: Clone + Display + Eq + Hash,
    H: HashID {
    /// Number of parties.
    nparties: usize,
    /// Quorum size.
    quorum: usize,
    /// The value for which we sent a prepare.
    prepared: PreparedReq<H, Req>,
    /// Prepare vote counts for each value.
    prepare_votes: HashMap<Req, BitVec>,
    /// Which parties have voted.
    prepare_voted: BitVec,
    /// Number of prepare votes remaining.
    prepare_remaining: usize,
    /// Number of prepare votes held by current leader.
    prepare_lead: usize,
    /// Commit vote counts for each value captured in the prepare
    /// phase.
    commit_votes: HashMap<Req, BitVec>,
    /// Bitmask of which parties have reported either completed or failed.
    ///
    /// This will cause the normal consistency checks on incoming
    /// votes to be omitted.
    completed: BitVec,
    /// Bitmask of which parties have voted to commit.
    commit_voted: BitVec,
    /// Number of commit votes remaining.
    commit_remaining: usize,
    /// Number of commit votes held by current leader.
    commit_lead: usize
}

/// PBFT state for the "commit" state.
pub struct CommitState<H, Req>
where
    Req: Clone + Display + Eq + Hash,
    H: HashID {
    hash: PhantomData<H>,
    /// Number of parties.
    nparties: usize,
    /// The value for which we sent a commit.
    commit: Option<Req>,
    /// Quorum size.
    quorum: usize,
    /// Bitmask of which parties have reported either completed or failed.
    ///
    /// This will cause the normal consistency checks on incoming
    /// votes to be omitted.
    completed: BitVec,
    /// Commit vote counts for each value.
    commit_votes: HashMap<Req, BitVec>,
    /// Bitmask of which parties have voted to commit.
    commit_voted: BitVec,
    /// Number of commit votes remaining.
    commit_remaining: usize,
    /// Number of commit votes held by current leader.
    commit_lead: usize
}

/// Information passed from the inter-round PBFT state to each round.
pub enum PBFTRoundInfo<Party> {
    /// Someone else is the leader.
    Other {
        /// The current leader.
        party: Party
    },
    /// We are the leader.
    This,
    /// No one is the leader.
    None
}

/// Per-round state machine for the Castro-Liskov PBFT consensus
/// protocol.
pub enum PBFTRoundState<H, Req>
where
    Req: Clone + Display + Eq + Hash,
    H: HashID {
    Prepare { prepare: PrepareState<H, Req> },
    Commit { commit: CommitState<H, Req> }
}

/// Round result for [PBFTRoundState].
pub enum PBFTRoundResult<Req> {
    /// The round successfully completed.
    Complete {
        /// The request that won.
        req: Req
    },
    /// The round failed.
    Fail {
        /// The final vote counts.
        fail: PBFTVoteCounts<Req>
    }
}

/// Vote counts from a failed PBFT round.
pub struct PBFTVoteCounts<Req> {
    prepare: Option<Vec<(Req, usize)>>,
    commit: Vec<(Req, usize)>
}

/// Errors that can occur creating a [PBFTRoundState].
pub enum PBFTRoundStateCreateError<Party> {
    BadParty { party: Party },
    BadHint { party: Party }
}

/// Errors that can occur creating a [PBFTProtoState].
pub enum PBFTProtoStateCreateError<Parties, Encode> {
    Parties { err: Parties },
    Encode { err: Encode }
}

/// Errors that can occur updating a [PBFTProtoState].
pub enum PBFTProtoStateUpdateError<H>
where
    H: Display + HashID {
    BadParty { id: H },
    BadSize { err: TryFromSliceError },
    BadPayload { size: usize }
}

#[derive(Debug)]
pub enum PBFTBatchError {
    Hash { err: TryFromSliceError },
    BadSize { size: usize }
}

fn payload_hashes<H>(
    hash: &H,
    bytes: &[u8]
) -> Result<Vec<H::HashID>, PBFTBatchError>
where
    H: HashAlgo {
    let nbytes = bytes.len();
    let hash_len = hash.hash_len();

    if nbytes.is_multiple_of(hash_len) {
        let nhashes = nbytes / hash_len;
        let mut hashes = Vec::with_capacity(nhashes);

        for i in 0..nhashes {
            let bytes = &bytes[hash_len * i..hash_len * (i + 1)];
            let hash = hash
                .wrap_hashed_bytes(bytes)
                .map_err(|err| PBFTBatchError::Hash { err: err })?;

            hashes.push(hash)
        }

        Ok(hashes)
    } else {
        Err(PBFTBatchError::BadSize { size: nbytes })
    }
}

impl<H, Req> OperBatch<H> for PBFTRoundResult<Req>
where
    Req: OperBatch<H>,
    H: HashAlgo
{
    type BatchError = Req::BatchError;

    fn take_batch(
        self,
        hash: &H
    ) -> Result<Option<Vec<H::HashID>>, Self::BatchError> {
        match self {
            PBFTRoundResult::Complete { req } => req.take_batch(hash),
            _ => Ok(None)
        }
    }
}

impl<H> OperBatch<H> for PbftRequest
where
    H: HashAlgo
{
    type BatchError = PBFTBatchError;

    fn take_batch(
        self,
        hash: &H
    ) -> Result<Option<Vec<H::HashID>>, Self::BatchError> {
        match self {
            PbftRequest::Payload(bytes) => {
                payload_hashes(hash, &bytes).map(Some)
            }
            _ => Ok(None)
        }
    }
}

impl<H> From<Vec<H>> for PbftRequest
where
    H: HashID
{
    fn from(hashes: Vec<H>) -> PbftRequest {
        let nhashes = hashes.len();
        let hash_len = hashes[0].hash_len();
        let mut bytes = vec![0; nhashes * hash_len];

        for (i, hash) in hashes.into_iter().enumerate() {
            bytes[hash_len * i..hash_len * (i + 1)]
                .copy_from_slice(hash.bytes());
        }

        PbftRequest::Payload(bytes)
    }
}

impl<RoundID> ConsensusProtoMsgTypes<RoundID> for PBFTProtoTypes
where
    RoundID: Clone + Display + Ord + From<u128> + Into<u128>
{
    type Msg = PbftMsg;
    type Payload = PbftContent;
}

impl<Types> ConsensusProtoOutboundTypes<Types> for PBFTProtoTypes
where
    Types: RoundPartyIdxTypes<PartyRoundIdx = OutboundPartyIdx>,
    Types::RoundID: From<u128> + Into<u128>
{
    type CollectOutboundError = Infallible;
    type Out = PBFTOutbound<Types::RoundID>;
    type RecvError = Infallible;
}

impl<H, Req> CommitState<H, Req>
where
    Req: Clone + Display + Eq + Hash,
    H: HashID
{
    /// Record a commit vote by a given party.
    ///
    /// This will not automatically record a prepare vote as well.
    ///
    /// This expects to only ever be called once for a given party.
    ///
    /// Returns whether the given vote won the commit vote.
    fn record_commit_votes<Round>(
        &mut self,
        round: &Round,
        lead_party: Option<usize>,
        self_party: usize,
        party: usize,
        request: &Req
    ) -> bool
    where
        Round: Display {
        if self_party != party {
            match self.commit_votes.entry(request.clone()) {
                // Entry already exists.
                Entry::Occupied(mut ent) => {
                    let votes = ent.get_mut();

                    // Add our own vote if we haven't voted already.
                    let is_lead_or_view =
                        lead_party.is_none_or(|lead| lead == party);

                    if is_lead_or_view && self.commit.is_none() {
                        votes.set(self_party, true);
                        self.commit_remaining -= 1;
                        self.commit_voted.set(self_party, true);
                        self.commit_lead =
                            self.commit_lead.max(votes.count_ones());
                        self.commit = Some(request.clone());

                        debug!(target: "pbft",
                               "self-vote recorded, {} remaining, lead has {}",
                               self.commit_remaining, self.commit_lead);
                    }

                    // Record party's vote.
                    if !votes[party] {
                        votes.set(party, true);
                        self.commit_voted.set(party, true);
                        self.commit_remaining -= 1;
                        self.commit_lead =
                            self.commit_lead.max(votes.count_ones());

                        debug!(target: "pbft",
                               concat!("commit vote recorded, {} remaining, ",
                                       "lead has {}"),
                               self.commit_remaining, self.commit_lead);

                        votes.count_ones() >= self.quorum
                    } else {
                        // Something went wrong if we get here.

                        error!(target: "pbft",
                               concat!("commit votes for {} for round {} ",
                                       "should not contain {}"),
                               request, round, party);

                        false
                    }
                }
                // No entry yet; create one.
                Entry::Vacant(ent) => {
                    let votes = ent.insert(bitvec![0; self.nparties]);

                    // Add our own vote if we haven't voted already.
                    let is_lead_or_view =
                        lead_party.is_none_or(|lead| lead == party);

                    if is_lead_or_view && self.commit.is_none() {
                        votes.set(self_party, true);
                        self.commit_remaining -= 1;
                        self.commit_voted.set(self_party, true);
                        self.commit_lead =
                            self.commit_lead.max(votes.count_ones());
                        self.commit = Some(request.clone());

                        debug!(target: "pbft",
                               "self-vote recorded, {} remaining, lead has {}",
                               self.commit_remaining, self.commit_lead);
                    }

                    // Record party's vote.
                    votes.set(party, true);
                    self.commit_voted.set(party, true);
                    self.commit_remaining -= 1;
                    self.commit_lead = self.commit_lead.max(votes.count_ones());

                    debug!(target: "pbft",
                           "commit vote recorded, {} remaining, lead has {}",
                           self.commit_remaining, self.commit_lead);

                    votes.count_ones() >= self.quorum
                }
            }
        } else {
            // If we get here, it's a recoverable error.

            error!(target: "pbft",
                   "attempt to record self-vote for {} for round {}",
                   request, round);

            false
        }
    }

    #[inline]
    fn has_failed(&self) -> bool {
        if self.commit_lead < self.quorum &&
            (self.quorum - self.commit_lead > self.commit_remaining)
        {
            debug!(target: "pbft",
                   concat!("lead commit candidate ({} votes) cannot ",
                           "reach quorum of {} with only {} ",
                           "votes remaining"),
                   self.commit_lead, self.quorum, self.commit_remaining);

            true
        } else {
            false
        }
    }

    /// Get the vote counts for this round.
    fn fail(self) -> PBFTVoteCounts<Req> {
        let commit = self
            .commit_votes
            .into_iter()
            .map(|(req, bits)| (req, bits.count_ones()))
            .collect();

        PBFTVoteCounts {
            commit: commit,
            prepare: None
        }
    }

    fn handle_fail<Round, Out>(
        mut self,
        out: &mut Out,
        round: &Round,
        party: usize
    ) -> RoundStateUpdate<PBFTRoundState<H, Req>, PBFTRoundResult<Req>>
    where
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        if !self.commit_voted[party] {
            debug!(target: "pbft",
                   "received fail from {} for round {}",
                   party, round);
            trace!(target: "pbft",
                   "logging fail for commit from {} for round {}",
                   party, round);

            self.completed.set(party, true);

            // Record the party as having voted and reduce the
            // remaining count, but don't cast any votes.
            self.commit_voted.set(party, true);
            self.commit_remaining -= 1;

            debug!(target: "pbft",
                   "fail vote recorded, {} remaining, lead has {}",
                   self.commit_remaining, self.commit_lead);

            if self.has_failed() {
                // The fail vote caused the round to fail.
                info!(target: "pbft",
                      "round failed due to failure votes by other parties");

                out.send_fail();

                // Transition to fail state.
                RoundStateUpdate::Resolved {
                    resolved: PBFTRoundResult::Fail { fail: self.fail() }
                }
            } else {
                // The round is still live.
                RoundStateUpdate::Pending {
                    pending: PBFTRoundState::Commit { commit: self }
                }
            }
        } else {
            trace!(target: "pbft",
                   concat!("received fail vote by {} in round {}, ",
                           "but vote was already recorded"),
                   party, round);

            RoundStateUpdate::Pending {
                pending: PBFTRoundState::Commit { commit: self }
            }
        }
    }

    /// Handle a `Commit` message.
    fn handle_commit<Round, Out>(
        self,
        out: &mut Out,
        round: &Round,
        lead_party: Option<usize>,
        party: usize,
        request: Req
    ) -> RoundStateUpdate<PBFTRoundState<H, Req>, PBFTRoundResult<Req>>
    where
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        self.handle_commit_complete(
            out, round, lead_party, party, request, false
        )
    }

    /// Handle a `Complete` message.
    fn handle_complete<Round, Out>(
        self,
        out: &mut Out,
        round: &Round,
        lead_party: Option<usize>,
        party: usize,
        request: Req
    ) -> RoundStateUpdate<PBFTRoundState<H, Req>, PBFTRoundResult<Req>>
    where
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        self.handle_commit_complete(
            out, round, lead_party, party, request, true
        )
    }

    /// Handle a `Commit` message.
    fn handle_commit_complete<Round, Out>(
        mut self,
        out: &mut Out,
        round: &Round,
        lead_party: Option<usize>,
        party: usize,
        request: Req,
        complete: bool
    ) -> RoundStateUpdate<PBFTRoundState<H, Req>, PBFTRoundResult<Req>>
    where
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        if self.commit_voted[party] {
            match self.commit_votes.get(&request) {
                Some(votes) => {
                    if votes[party] {
                        // This is ok, just a redundant message.

                        trace!(target: "pbft",
                               concat!("received redundant commit ",
                                       "vote ({}) by {} in round {}"),
                               request, party, round)
                    } else if !self.completed[party] && !complete {
                        // Something's wrong: the party is listed as
                        // voting, but not for this value.
                        //
                        // We omit this check if a party is marked as
                        // having reported completion or failure, as
                        // this can contradict their vote.

                        warn!(target: "pbft",
                      concat!("party {} sent commit vote ",
                              "({}) for round {}, is listed ",
                              "as voting, but not present in ",
                              "votes for proposal"),
                      party, request, round);
                    }
                }
                None if !self.completed[party] && !complete => {
                    // The party is listed as having voted, but no
                    // record exists for this proposal for this round.
                    //
                    // We omit this check if a party is marked as
                    // having reported completion or failure, as this
                    // can contradict their vote.

                    warn!(target: "pbft",
                      concat!("party {} sent commit vote ",
                              "({}) for round {}, is listed ",
                              "as voting, but no votes exist ",
                              "for proposal"),
                      party, request, round);
                }
                _ => {}
            }

            RoundStateUpdate::Pending {
                pending: PBFTRoundState::Commit { commit: self }
            }
        } else {
            // This party has not yet voted to commit; we're good.
            if complete {
                debug!(target: "pbft",
                   "received complete ({}) from {} for round {}",
                   request, party, round);

                self.completed.set(party, true);
            } else {
                debug!(target: "pbft",
                   "received commit ({}) from {} for round {}",
                   request, party, round);
            }

            if !self.commit_voted[party] {
                trace!(target: "pbft",
                   "logging commit vote for {} from {} for round {}",
                   request, party, round);

                let commit_was_empty = self.commit.is_none();

                // Log the commit vote.
                if self.record_commit_votes(
                    round, lead_party, SELF_PARTY, party, &request
                ) {
                    info!(target: "pbft",
                      "proposal {} has won commit vote for round {}",
                      request, round);

                    // Send complete messages.
                    out.send_complete(&request);

                    // Transition into complete state.
                    RoundStateUpdate::Resolved {
                        resolved: PBFTRoundResult::Complete { req: request }
                    }
                } else if self.has_failed() {
                    info!(target: "pbft",
                      "round failed in commit phase");

                    out.send_fail();

                    // Transition to fail state
                    RoundStateUpdate::Resolved {
                        resolved: PBFTRoundResult::Fail { fail: self.fail() }
                    }
                } else {
                    if commit_was_empty && let Some(commit) = &self.commit {
                        out.send_commit(commit);
                    }

                    RoundStateUpdate::Pending {
                        pending: PBFTRoundState::Commit { commit: self }
                    }
                }
            } else {
                RoundStateUpdate::Pending {
                    pending: PBFTRoundState::Commit { commit: self }
                }
            }
        }
    }
}

impl<H, Req> PrepareState<H, Req>
where
    Req: Clone + Display + Eq + Hash,
    H: HashID
{
    /// Create a new `PrepareState` for a non-leader node.
    fn new(
        nparties: usize,
        deadline: Option<Instant>,
        leader_vote: H
    ) -> Self {
        let nfaults = (nparties - 1) / 3;
        let quorum = nparties - nfaults;
        let prepared = PreparedReq::None {
            leader_vote: leader_vote,
            deadline: deadline
        };

        debug!(target: "pbft",
               "originating round with no prepare vote from us");

        PrepareState {
            quorum: quorum,
            nparties: nparties,
            prepared: prepared,
            prepare_votes: HashMap::with_capacity(2),
            prepare_voted: bitvec![0; nparties],
            prepare_remaining: nparties,
            prepare_lead: 0,
            commit_votes: HashMap::with_capacity(2),
            commit_voted: bitvec![0; nparties],
            completed: bitvec![0; nparties],
            commit_remaining: nparties,
            commit_lead: 0
        }
    }

    /// Create a new `PBFTRoundState` for a leader.
    fn with_req(
        nparties: usize,
        request: Req
    ) -> Self {
        let nfaults = (nparties - 1) / 3;
        let quorum = nparties - nfaults;

        debug!(target: "pbft",
               "originating round with our prepare vote for {}",
               request);

        // Record our own vote.
        let mut votes = bitvec![0; nparties];
        let mut prepare_votes = HashMap::with_capacity(2);
        let mut prepare_voted = bitvec![0; nparties];

        votes.set(0, true);
        prepare_votes.insert(request.clone(), votes);
        prepare_voted.set(0, true);

        PrepareState {
            quorum: quorum,
            nparties: nparties,
            prepared: PreparedReq::Prepared { req: request },
            prepare_votes: prepare_votes,
            prepare_voted: prepare_voted,
            prepare_remaining: nparties - 1,
            prepare_lead: 1,
            commit_votes: HashMap::with_capacity(2),
            commit_voted: bitvec![0; nparties],
            completed: bitvec![0; nparties],
            commit_remaining: nparties,
            commit_lead: 0
        }
    }

    /// Convert this into a [CommitState].
    #[inline]
    fn into_commit(self) -> CommitState<H, Req> {
        let commit = match self.prepared {
            PreparedReq::Prepared { req } => Some(req),
            PreparedReq::None { .. } => None
        };

        CommitState {
            hash: PhantomData,
            nparties: self.nparties,
            quorum: self.quorum,
            completed: self.completed,
            commit: commit,
            commit_remaining: self.commit_remaining,
            commit_votes: self.commit_votes,
            commit_voted: self.commit_voted,
            commit_lead: self.commit_lead
        }
    }

    /// Record a commit vote by a given party.
    ///
    /// This will not automatically record a prepare vote as well.
    ///
    /// This expects to only ever be called once for a given party.
    ///
    /// Returns whether the given vote won the commit vote.
    fn record_commit_votes<Round>(
        &mut self,
        round: &Round,
        self_party: usize,
        party: usize,
        request: &Req
    ) -> bool
    where
        Round: Display {
        if self_party != party {
            match self.commit_votes.entry(request.clone()) {
                // Entry already exists.
                Entry::Occupied(mut ent) => {
                    let votes = ent.get_mut();

                    if !votes[party] {
                        votes.set(party, true);
                        self.commit_voted.set(party, true);
                        self.commit_remaining -= 1;
                        self.commit_lead =
                            self.commit_lead.max(votes.count_ones());

                        debug!(target: "pbft",
                               concat!("commit vote recorded, {} remaining, ",
                                       "lead has {}"),
                               self.commit_remaining, self.commit_lead);

                        votes.count_ones() >= self.quorum
                    } else {
                        // Something went wrong if we get here.

                        error!(target: "pbft",
                               concat!("commit votes for {} for round {} ",
                                       "should not contain {}"),
                               request, round, party);

                        false
                    }
                }
                // No entry yet; create one.
                Entry::Vacant(ent) => {
                    let votes = ent.insert(bitvec![0; self.nparties]);

                    votes.set(party, true);
                    self.commit_voted.set(party, true);
                    self.commit_remaining -= 1;
                    self.commit_lead = self.commit_lead.max(votes.count_ones());

                    debug!(target: "pbft",
                           "commit vote recorded, {} remaining, lead has {}",
                           self.commit_remaining, self.commit_lead);

                    votes.count_ones() >= self.quorum
                }
            }
        } else {
            // If we get here, it's a recoverable error.

            error!(target: "pbft",
                   "attempt to record self-vote for {} for round {}",
                   request, round);

            false
        }
    }

    fn record_self_commit<Round>(
        &mut self,
        round: &Round,
        self_party: usize
    ) -> bool
    where
        Round: Display {
        if let PreparedReq::Prepared { req } = &self.prepared {
            match self.commit_votes.entry(req.clone()) {
                // Entry already exists.
                Entry::Occupied(mut ent) => {
                    let votes = ent.get_mut();

                    if !votes[self_party] {
                        votes.set(self_party, true);
                        self.commit_voted.set(self_party, true);
                        self.commit_remaining -= 1;
                        self.commit_lead =
                            self.commit_lead.max(votes.count_ones());

                        debug!(target: "pbft",
                               concat!("commit self-vote recorded, {} ",
                                       "remaining, lead has {}"),
                               self.commit_remaining, self.commit_lead);
                    } else {
                        error!(target: "pbft",
                               concat!("commit self-vote already recorded ",
                                       "for {} in round {}"),
                               req, round)
                    }

                    votes.count_ones() >= self.quorum
                }
                // No entry yet; create one.
                Entry::Vacant(ent) => {
                    let votes = ent.insert(bitvec![0; self.nparties]);

                    votes.set(self_party, true);
                    self.commit_voted.set(self_party, true);
                    self.commit_remaining -= 1;
                    self.commit_lead = self.commit_lead.max(votes.count_ones());

                    debug!(target: "pbft",
                           concat!("commit self-vote recorded, {} ",
                                   "remaining, lead has {}"),
                           self.commit_remaining, self.commit_lead);

                    votes.count_ones() >= self.quorum
                }
            }
        } else {
            false
        }
    }

    /// Record a prepare vote by a given party.
    ///
    /// This will also cause us to issue a prepare vote, if we haven't
    /// already.
    ///
    /// This expects to only ever be called once for a given party.
    ///
    /// Returns whether the given vote won the prepare vote.
    fn record_prepare_votes<Round>(
        &mut self,
        round: &Round,
        lead_party: Option<usize>,
        self_party: usize,
        party: usize,
        request: &Req
    ) -> bool
    where
        Round: Display {
        if let Some(lead_party) = lead_party {
            trace!(target: "pbft",
                   "logging prepare vote for {} from {} for round {} ({})",
                   request, party, round, lead_party);
        } else {
            trace!(target: "pbft",
                   "logging prepare vote for {} from {} for round {} (none)",
                   request, party, round);
        }

        if self_party != party {
            match self.prepare_votes.entry(request.clone()) {
                // Entry already exists.
                Entry::Occupied(mut ent) => {
                    let votes = ent.get_mut();

                    // Add our own vote if we haven't voted already.
                    let is_lead_or_view =
                        lead_party.is_none_or(|lead| lead == party);

                    if is_lead_or_view &&
                        matches!(self.prepared, PreparedReq::None { .. })
                    {
                        votes.set(self_party, true);
                        self.prepare_remaining -= 1;
                        self.prepare_voted.set(self_party, true);
                        self.prepare_lead =
                            self.prepare_lead.max(votes.count_ones());
                        self.prepared = PreparedReq::Prepared {
                            req: request.clone()
                        };

                        debug!(target: "pbft",
                               "self-vote recorded, {} remaining, lead has {}",
                               self.prepare_remaining, self.prepare_lead);
                    }

                    // Record party's vote
                    votes.set(party, true);
                    self.prepare_voted.set(party, true);
                    self.prepare_remaining -= 1;
                    self.prepare_lead =
                        self.prepare_lead.max(votes.count_ones());

                    debug!(target: "pbft",
                           "prepare vote recorded, {} remaining, lead has {}",
                           self.prepare_remaining, self.prepare_lead);

                    votes.count_ones() >= self.quorum
                }
                // No entry yet; create one.
                Entry::Vacant(ent) => {
                    let votes = ent.insert(bitvec![0; self.nparties]);

                    // Add our own vote if we haven't voted already.
                    let is_lead_or_view =
                        lead_party.is_none_or(|lead| lead == party);

                    if is_lead_or_view &&
                        matches!(self.prepared, PreparedReq::None { .. })
                    {
                        votes.set(self_party, true);
                        self.prepare_remaining -= 1;
                        self.prepare_voted.set(self_party, true);
                        self.prepare_lead =
                            self.prepare_lead.max(votes.count_ones());
                        self.prepared = PreparedReq::Prepared {
                            req: request.clone()
                        };

                        debug!(target: "pbft",
                               "self-vote recorded, {} remaining, lead has {}",
                               self.prepare_remaining, self.prepare_lead);
                    }

                    // Record party's vote
                    votes.set(party, true);
                    self.prepare_voted.set(party, true);
                    self.prepare_remaining -= 1;
                    self.prepare_lead =
                        self.prepare_lead.max(votes.count_ones());

                    debug!(target: "pbft",
                           "prepare vote recorded, {} remaining, lead has {}",
                           self.prepare_remaining, self.prepare_lead);

                    votes.count_ones() >= self.quorum
                }
            }
        } else {
            // If we get here, it's a recoverable error.

            error!(target: "pbft",
                   "attempt to record self-vote for {} for round {}",
                   request, round);

            false
        }
    }

    #[inline]
    fn has_failed(&self) -> bool {
        if self.prepare_lead < self.quorum &&
            (self.quorum - self.prepare_lead > self.prepare_remaining)
        {
            debug!(target: "pbft",
                   concat!("lead prepare candidate ({} votes) cannot ",
                           "reach quorum of {} with only {} ",
                           "votes remaining"),
                   self.prepare_lead, self.quorum, self.prepare_remaining);

            true
        } else if self.commit_lead < self.quorum &&
            (self.quorum - self.commit_lead > self.commit_remaining)
        {
            debug!(target: "pbft",
                   concat!("lead commit candidate ({} votes) cannot ",
                           "reach quorum of {} with only {} ",
                           "votes remaining"),
                   self.commit_lead, self.quorum, self.commit_remaining);

            true
        } else {
            false
        }
    }

    /// Get the vote counts for this round.
    fn fail(self) -> PBFTVoteCounts<Req> {
        let commit = self
            .commit_votes
            .into_iter()
            .map(|(req, bits)| (req, bits.count_ones()))
            .collect();
        let prepare = self
            .prepare_votes
            .into_iter()
            .map(|(req, bits)| (req, bits.count_ones()))
            .collect();

        PBFTVoteCounts {
            prepare: Some(prepare),
            commit: commit
        }
    }

    fn handle_fail<Round, Out>(
        mut self,
        out: &mut Out,
        round: &Round,
        party: usize
    ) -> RoundStateUpdate<PBFTRoundState<H, Req>, PBFTRoundResult<Req>>
    where
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        if !self.commit_voted[party] || !self.prepare_voted[party] {
            debug!(target: "pbft",
               "received fail from {} for round {}",
               party, round);

            self.completed.set(party, true);

            if !self.prepare_voted[party] {
                // Record the party as having voted and reduce the
                // remaining count, but don't cast any votes.
                trace!(target: "pbft",
                   "logging fail for prepare from {} for round {}",
                   party, round);

                self.prepare_voted.set(party, true);
                self.prepare_remaining -= 1;

                debug!(target: "pbft",
                   "fail prepare vote recorded, {} remaining, lead has {}",
                   self.prepare_remaining, self.prepare_lead);
            }

            if !self.commit_voted[party] {
                // Record the party as having voted and reduce the
                // remaining count, but don't cast any votes.
                trace!(target: "pbft",
                   "logging fail for commit from {} for round {}",
                   party, round);

                self.commit_voted.set(party, true);
                self.commit_remaining -= 1;

                debug!(target: "pbft",
                   "fail commit vote recorded, {} remaining, lead has {}",
                   self.commit_remaining, self.commit_lead);
            }

            if self.has_failed() {
                // The fail vote caused the round to fail.
                info!(target: "pbft",
                  "round failed due to failure votes by other parties");

                out.send_fail();

                // Transition to fail state.
                RoundStateUpdate::Resolved {
                    resolved: PBFTRoundResult::Fail { fail: self.fail() }
                }
            } else {
                // The round is still live.

                RoundStateUpdate::Pending {
                    pending: PBFTRoundState::Prepare { prepare: self }
                }
            }
        } else {
            trace!(target: "pbft",
               concat!("received fail vote by {} in round {}, ",
                       "but vote was already recorded"),
               party, round);

            RoundStateUpdate::Pending {
                pending: PBFTRoundState::Prepare { prepare: self }
            }
        }
    }

    /// Handle a `Prepare` message.
    fn handle_prepare<Round, Out>(
        mut self,
        out: &mut Out,
        round: &Round,
        lead_party: Option<usize>,
        party: usize,
        request: Req
    ) -> RoundStateUpdate<PBFTRoundState<H, Req>, PBFTRoundResult<Req>>
    where
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        if self.prepare_voted[party] {
            match self.prepare_votes.get(&request) {
                Some(votes) => {
                    if votes[party] {
                        // This is ok, just a redundant message.

                        trace!(target: "pbft",
                       concat!("received redundant prepare ",
                               "vote ({}) by {} in round {}"),
                       request, party, round)
                    } else if !self.completed[party] {
                        // Something's wrong: the party is listed as
                        // voting, but not for this value.
                        //
                        // We omit this check if a party is marked as
                        // having reported completion or failure, as
                        // this can contradict their vote.

                        warn!(target: "pbft",
                      concat!("party {} sent prepare vote ",
                              "({}) for round {}, is listed ",
                              "as voting, but not present in ",
                              "votes for proposal"),
                      party, request, round);
                    }
                }
                None if !self.completed[party] => {
                    // The party is listed as having voted, but no
                    // record exists for this proposal for this round.
                    //
                    // We omit this check if a party is marked as
                    // having reported completion or failure, as this
                    // can contradict their vote.

                    warn!(target: "pbft",
                      concat!("party {} sent prepare vote ",
                              "({}) for round {}, is listed ",
                              "as voting, but no votes exist ",
                              "for proposal"),
                      party, request, round);
                }
                _ => {}
            }

            RoundStateUpdate::Pending {
                pending: PBFTRoundState::Prepare { prepare: self }
            }
        } else {
            // This party has not yet voted to prepare; we're good.
            debug!(target: "pbft",
               "received prepare ({}) from {} for round {}",
               request, party, round);

            let prepared_was_empty =
                matches!(self.prepared, PreparedReq::None { .. });

            // Record the prepare vote.
            if self.record_prepare_votes(
                round, lead_party, SELF_PARTY, party, &request
            ) {
                // The request has won the prepare vote.
                info!(target: "pbft",
                  "{} won prepare vote for round {}",
                  request, round);
                trace!(target: "pbft",
                   "logging our commit vote for {} for round {}",
                   request, round);

                // Record our commit vote.
                if self.record_self_commit(round, SELF_PARTY) {
                    // Our commit vote caused the request to win the
                    // round.  Go straight to complete.
                    info!(target: "pbft",
                      "{} won commit vote for round {}",
                      request, round);

                    // Send complete messages.
                    out.send_complete(&request);

                    RoundStateUpdate::Resolved {
                        resolved: PBFTRoundResult::Complete { req: request }
                    }
                } else if self.has_failed() {
                    info!(target: "pbft",
                      "round failed in commit phase");

                    out.send_fail();

                    // Transition to fail state
                    RoundStateUpdate::Resolved {
                        resolved: PBFTRoundResult::Fail { fail: self.fail() }
                    }
                } else {
                    // Begin the commit phase.
                    debug!(target: "pbft",
                           "entering commit phase for round {}",
                           round);

                    if let PreparedReq::Prepared { req } = &self.prepared {
                        out.send_commit(req);
                    } else {
                        error!(target: "pbft",
                               "entering commit phase with no prepared vote");
                    }

                    RoundStateUpdate::Pending {
                        pending: PBFTRoundState::Commit {
                            commit: self.into_commit()
                        }
                    }
                }
            } else if self.has_failed() {
                info!(target: "pbft",
                  "round failed in prepare phase");

                out.send_fail();

                // Transition to fail state
                RoundStateUpdate::Resolved {
                    resolved: PBFTRoundResult::Fail { fail: self.fail() }
                }
            } else {
                if let PreparedReq::Prepared { req } = &self.prepared &&
                    prepared_was_empty
                {
                    out.send_prepare(req);
                }

                // Not enough votes to decide the round.
                RoundStateUpdate::Pending {
                    pending: PBFTRoundState::Prepare { prepare: self }
                }
            }
        }
    }

    /// Handle a `Commit` message.
    fn handle_commit<Round, Out>(
        self,
        out: &mut Out,
        round: &Round,
        lead_party: Option<usize>,
        party: usize,
        request: Req
    ) -> RoundStateUpdate<PBFTRoundState<H, Req>, PBFTRoundResult<Req>>
    where
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        self.handle_commit_complete(
            out, round, lead_party, party, request, false
        )
    }

    /// Handle a `Complete` message.
    fn handle_complete<Round, Out>(
        self,
        out: &mut Out,
        round: &Round,
        lead_party: Option<usize>,
        party: usize,
        request: Req
    ) -> RoundStateUpdate<PBFTRoundState<H, Req>, PBFTRoundResult<Req>>
    where
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        self.handle_commit_complete(
            out, round, lead_party, party, request, true
        )
    }

    /// Utility function for handling both commit and complete.
    fn handle_commit_complete<Round, Out>(
        mut self,
        out: &mut Out,
        round: &Round,
        lead_party: Option<usize>,
        party: usize,
        request: Req,
        complete: bool
    ) -> RoundStateUpdate<PBFTRoundState<H, Req>, PBFTRoundResult<Req>>
    where
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        if self.commit_voted[party] {
            match self.prepare_votes.get(&request) {
                Some(votes) => {
                    if votes[party] {
                        // This is ok, just a redundant message.

                        trace!(target: "pbft",
                       concat!("received redundant commit ",
                               "vote ({}) by {} in round {}"),
                       request, party, round)
                    } else if !self.completed[party] && !complete {
                        // Something's wrong: the party is listed as
                        // voting, but not for this value.
                        //
                        // We omit this check if a party is marked as
                        // having reported completion or failure, as
                        // this can contradict their vote.

                        warn!(target: "pbft",
                      concat!("party {} sent commit vote ",
                              "({}) for round {}, is listed ",
                              "as voting, but not present in ",
                              "votes for proposal"),
                      party, request, round);
                    }
                }
                None if !self.completed[party] && !complete => {
                    // The party is listed as having voted, but no
                    // record exists for this proposal for this round.
                    //
                    // We omit this check if a party is marked as
                    // having reported completion or failure, as this
                    // can contradict their vote.

                    warn!(target: "pbft",
                      concat!("party {} sent commit vote ",
                              "({}) for round {}, is listed ",
                              "as voting, but no votes exist ",
                              "for proposal"),
                      party, request, round);
                }
                _ => {}
            }

            RoundStateUpdate::Pending {
                pending: PBFTRoundState::Prepare { prepare: self }
            }
        } else {
            // This party has not yet voted to commit; we're good.
            if complete {
                debug!(target: "pbft",
                   "received complete ({}) from {} for round {}",
                   request, party, round);

                self.completed.set(party, true);
            } else {
                debug!(target: "pbft",
                   "received commit ({}) from {} for round {}",
                   request, party, round);
            }

            // First, see if we need to record a prepare vote
            if !self.prepare_voted[party] {
                // We need to record a prepare vote.
                let is_lead_or_view =
                    lead_party.is_none_or(|lead| lead == party);

                if is_lead_or_view &&
                    matches!(self.prepared, PreparedReq::None { .. })
                {
                    out.send_prepare(&request);
                }

                // Record the prepare vote.
                if self.record_prepare_votes(
                    round, lead_party, SELF_PARTY, party, &request
                ) {
                    // The request has won the prepare vote.
                    info!(target: "pbft",
                      "{} won prepare vote for round {}",
                      request, round);
                    trace!(target: "pbft",
                       "logging our commit vote for {} for round {}",
                       request, round);

                    // Record our commit vote.
                    if self.record_self_commit(round, SELF_PARTY) {
                        // Our commit vote caused the request to win
                        // the round.  Go straight to complete.
                        info!(target: "pbft",
                          "{} won commit vote for round {}",
                          request, round);

                        // Send complete messages.
                        out.send_complete(&request);

                        return RoundStateUpdate::Resolved {
                            resolved: PBFTRoundResult::Complete {
                                req: request
                            }
                        };
                    } else if self.has_failed() {
                        info!(target: "pbft",
                          "round failed in commit phase");

                        out.send_fail();

                        // Transition to fail state
                        return RoundStateUpdate::Resolved {
                            resolved: PBFTRoundResult::Fail {
                                fail: self.fail()
                            }
                        };
                    } else {
                        // Begin the commit phase.
                        debug!(target: "pbft",
                           "entering commit phase for round {}",
                           round);

                        if let PreparedReq::Prepared { req } = &self.prepared {
                            out.send_commit(req);
                        } else {
                            error!(target: "pbft",
                                   concat!("entering commit phase ",
                                           "with no prepared vote"));
                        }

                        // Transition to the commit state and handle
                        // the commit vote there.
                        let commit = self.into_commit();

                        return commit.handle_commit_complete(
                            out, round, lead_party, party, request, complete
                        );
                    }
                } else if self.has_failed() {
                    info!(target: "pbft",
                      "round failed in prepare phase");

                    out.send_fail();

                    // Transition to fail state
                    return RoundStateUpdate::Resolved {
                        resolved: PBFTRoundResult::Fail { fail: self.fail() }
                    };
                }
            }

            if !self.commit_voted[party] {
                trace!(target: "pbft",
                   "logging commit vote for {} from {} for round {}",
                   request, party, round);

                // Now, record the actual commit vote.
                if self.record_commit_votes(&round, SELF_PARTY, party, &request)
                {
                    // The request won the commit vote outright.
                    info!(target: "pbft",
                      concat!("proposal {} has won commit ",
                              "vote for round {}"),
                      request, round);

                    // Still request to send commit messages,
                    // for the sake of the other parties.
                    out.send_complete(&request);

                    // Transition into complete state.
                    RoundStateUpdate::Resolved {
                        resolved: PBFTRoundResult::Complete { req: request }
                    }
                } else if self.has_failed() {
                    // The commit vote is deadlocked.
                    info!(target: "pbft",
                      "round failed in prepare phase");

                    out.send_fail();

                    // Transition to fail state
                    RoundStateUpdate::Resolved {
                        resolved: PBFTRoundResult::Fail { fail: self.fail() }
                    }
                } else {
                    // The round is still unresolved.

                    RoundStateUpdate::Pending {
                        pending: PBFTRoundState::Prepare { prepare: self }
                    }
                }
            } else {
                // The round is still unresolved.

                RoundStateUpdate::Pending {
                    pending: PBFTRoundState::Prepare { prepare: self }
                }
            }
        }
    }
}

impl<H, Req> PBFTRoundState<H, Req>
where
    Req: Clone + Display + Eq + Hash,
    H: HashID
{
    /// Create a new `PBFTRoundState` for a non-leader party.
    #[inline]
    fn new(
        nparties: usize,
        deadline: Option<Instant>,
        leader_vote: H
    ) -> Self {
        PBFTRoundState::Prepare {
            prepare: PrepareState::new(nparties, deadline, leader_vote)
        }
    }

    /// Create a new `PBFTRoundState` for a leader.
    #[inline]
    fn with_req<Out>(
        out: &mut Out,
        nparties: usize,
        request: Req
    ) -> Self
    where
        Out: PBFTOutboundSend<Req> {
        // Send out prepare messages.
        out.send_prepare(&request);

        PBFTRoundState::Prepare {
            prepare: PrepareState::with_req(nparties, request)
        }
    }

    /// Handle a `Prepare` message.
    fn prepare<Round, Out>(
        self,
        out: &mut Out,
        round: &Round,
        info: &PBFTRoundInfo<OutboundPartyIdx>,
        party: &OutboundPartyIdx,
        request: Req,
        ignore_leader: bool
    ) -> RoundStateUpdate<Self, PBFTRoundResult<Req>>
    where
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        let party: usize = party.clone().into();
        let party = party + 1;
        let lead_party: Option<usize> = if ignore_leader {
            None
        } else {
            match info {
                PBFTRoundInfo::Other { party } => Some(party.clone().into()),
                PBFTRoundInfo::This => Some(SELF_PARTY),
                PBFTRoundInfo::None => None
            }
        };

        match self {
            // This is the main body; everything else is a disregard case.
            PBFTRoundState::Prepare { prepare: state } => {
                state.handle_prepare(out, round, lead_party, party, request)
            }
            // Someone sent us a prepare when we're in the commit
            // phase.  Disregard, but this could be just stale
            // messages.
            PBFTRoundState::Commit { commit: state } => {
                debug!(target: "pbft",
                       concat!("received prepare ({}) for round {} ",
                               "from {} when already in commit phase"),
                       request, round, party);

                RoundStateUpdate::Pending {
                    pending: PBFTRoundState::Commit { commit: state }
                }
            }
        }
    }

    /// Handle a `Commit` message.
    fn commit<Round, Out>(
        self,
        out: &mut Out,
        round: &Round,
        info: &PBFTRoundInfo<OutboundPartyIdx>,
        party: &OutboundPartyIdx,
        request: Req,
        ignore_leader: bool
    ) -> RoundStateUpdate<Self, PBFTRoundResult<Req>>
    where
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        let party: usize = party.clone().into();
        let party = party + 1;
        let lead_party: Option<usize> = if ignore_leader {
            None
        } else {
            match info {
                PBFTRoundInfo::Other { party } => Some(party.clone().into()),
                PBFTRoundInfo::This => Some(SELF_PARTY),
                PBFTRoundInfo::None => None
            }
        };

        match self {
            // We got a commit message in the prepare state; this is
            // potentially valid.
            PBFTRoundState::Prepare { prepare: state } => {
                state.handle_commit(out, round, lead_party, party, request)
            }
            PBFTRoundState::Commit { commit: state } => {
                state.handle_commit(out, round, lead_party, party, request)
            }
        }
    }

    /// Handle a `Complete` message.
    fn complete<Round, Out>(
        self,
        out: &mut Out,
        round: &Round,
        lead_party: &PBFTRoundInfo<OutboundPartyIdx>,
        party: &OutboundPartyIdx,
        request: Req
    ) -> RoundStateUpdate<Self, PBFTRoundResult<Req>>
    where
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        let party: usize = party.clone().into();
        let party = party + 1;
        let lead_party: Option<usize> = match lead_party {
            PBFTRoundInfo::Other { party } => Some(party.clone().into()),
            PBFTRoundInfo::This => Some(SELF_PARTY),
            PBFTRoundInfo::None => None
        };

        match self {
            // We got a commit message in the prepare state; this is
            // potentially valid.
            PBFTRoundState::Prepare { prepare: state } => {
                state.handle_complete(out, round, lead_party, party, request)
            }
            PBFTRoundState::Commit { commit: state } => {
                state.handle_complete(out, round, lead_party, party, request)
            }
        }
    }

    /// Handle a `Fail` message.
    fn fail<Party, Round, Out>(
        self,
        out: &mut Out,
        round: &Round,
        party: &Party
    ) -> RoundStateUpdate<Self, PBFTRoundResult<Req>>
    where
        Party: Clone + Display + From<usize> + Into<usize>,
        Out: PBFTOutboundSend<Req>,
        Round: Display {
        let party: usize = party.clone().into() + 1;

        match self {
            // We got a commit message in the prepare state; this is
            // potentially valid.
            PBFTRoundState::Prepare { prepare: state } => {
                state.handle_fail(out, round, party)
            }
            PBFTRoundState::Commit { commit: state } => {
                state.handle_fail(out, round, party)
            }
        }
    }
}

impl<H, Party> PBFTProtoState<H, Party>
where
    Party: Clone + Display + Eq + Hash,
    H: Default + HashAlgo,
    H::HashID: Clone + Display + Eq + Hash
{
    #[inline]
    fn nparties(&self) -> usize {
        self.party_hashes.len() + 1
    }

    fn hash_to_party(
        &self,
        id: &[u8]
    ) -> Result<PBFTLeaderHint<Party>, PBFTProtoStateUpdateError<H::HashID>>
    {
        let id = self
            .hash
            .wrap_hashed_bytes(id)
            .map_err(|err| PBFTProtoStateUpdateError::BadSize { err: err })?;

        if id == self.self_hash {
            Ok(PBFTLeaderHint::This)
        } else {
            match self.hash_parties.get(&id) {
                Some(party) => Ok(PBFTLeaderHint::Other {
                    party: party.clone()
                }),
                None => Err(PBFTProtoStateUpdateError::BadParty { id: id })
            }
        }
    }

    fn highest_votes(
        &self,
        votes: &PBFTVoteCounts<PbftRequest>
    ) -> Result<Vec<PBFTLeaderHint<Party>>, PBFTProtoStateUpdateError<H::HashID>>
    {
        let size = votes.commit.len();
        let size = votes
            .prepare
            .as_ref()
            .map_or(size, |votes| size.max(votes.len()));
        let mut max = 0;
        let mut best = Vec::with_capacity(size);

        // Run through the commit votes.
        for (req, nvotes) in votes.commit.iter() {
            // If it's a view change request, update the
            // best votes.
            if *nvotes >= max &&
                let PbftRequest::View(PbftView { id }) = req
            {
                let party = self.hash_to_party(id)?;

                if *nvotes == max {
                    best.clear()
                }

                max = *nvotes;
                best.push(party.clone())
            }
        }

        // Run through the prepare votes if we have them.
        if let Some(prepare_votes) = &votes.prepare {
            for (req, nvotes) in prepare_votes.iter() {
                // If it's a view change request, update the
                // best votes.
                if *nvotes >= max &&
                    let PbftRequest::View(PbftView { id }) = req
                {
                    let party = self.hash_to_party(id)?;

                    if *nvotes == max {
                        best.clear()
                    }

                    max = *nvotes;
                    best.push(party.clone())
                }
            }
        }

        Ok(best)
    }

    fn update_leader_hint(
        &mut self,
        votes: &PBFTVoteCounts<PbftRequest>
    ) -> Result<(), PBFTProtoStateUpdateError<H::HashID>> {
        // If there is no leader, update the hint.
        if let PBFTLeader::None { .. } = &self.leader {
            let mut best = self.highest_votes(votes)?;

            // ISSUE #4: this is a bad method; replace it with
            // something better.
            if let PBFTLeader::None { hint } = &mut self.leader {
                if best.len() > 1 {
                    let idx = random::<usize>() % best.len();

                    *hint = Some(best[idx].clone());
                } else {
                    *hint = best.pop()
                }
            }
        }

        Ok(())
    }
}

impl<H, Party> ProtoStateSubmit<H::HashID> for PBFTProtoState<H, Party>
where
    H: Default + HashAlgo,
    H::HashID: Clone + Display + Eq + Hash,
    Party: Clone + Display + Eq + Hash
{
    type SubmitError = Infallible;

    #[inline]
    fn submit_reqs<I>(
        &mut self,
        hashes: I
    ) -> Result<(), Self::SubmitError>
    where
        I: Iterator<Item = H::HashID> {
        // Actually submit the hashes.
        self.pending.submit_hashes(hashes);

        if let PBFTLeader::Other { stall_start, .. } = &mut self.leader {
            *stall_start = Some(Instant::now());
        }

        Ok(())
    }
}

impl<H, Types> ProtoStateSetParties<Types> for PBFTProtoState<H, Types::PartyID>
where
    H: Default + HashAlgo,
    H::HashID: Clone + Display + Eq + Hash,
    Types: PartyTypes + RoundPartyIDTypes
{
    type SetPartiesError = Types::EncodeError;

    fn set_parties(
        &mut self,
        mut codec: Types::PartyCodec,
        self_party: Types::Party,
        party_data: &[Types::Party]
    ) -> Result<Vec<Option<Types::PartyID>>, Self::SetPartiesError> {
        let len = party_data.len();
        let self_hash = self.hash.hashid(&mut codec, &self_party)?;
        let party_hashes = HashMap::with_capacity(len);
        let hash_parties = HashMap::with_capacity(len);
        let old_hash_parties = replace(&mut self.hash_parties, hash_parties);
        let mut party_map = Vec::with_capacity(len);

        self.self_hash = self_hash;
        self.party_hashes = party_hashes;

        for (i, party) in party_data.iter().enumerate() {
            let party_id = Types::PartyID::from(i);
            let hash = self.hash.hashid(&mut codec, party)?;

            party_map.push(old_hash_parties.get(&hash).cloned());
            self.party_hashes.insert(party_id.clone(), hash.clone());
            self.hash_parties.insert(hash, party_id.clone());
        }

        Ok(party_map)
    }
}

impl<H, Types> ProtoState<Types> for PBFTProtoState<H, Types::PartyID>
where
    H: Default + HashAlgo,
    H::HashID: Clone + Display + Eq + Hash,
    Types: PartyTypes + RoundPartyIDTypes
{
    type Config = PBFTProtoStateConfig;
    type CreateError = Infallible;
    type Oper = PBFTRoundResult<PbftRequest>;
    type UpdateError = PBFTProtoStateUpdateError<H::HashID>;

    fn create(config: Self::Config) -> Result<Self, Self::CreateError> {
        let (
            outbound_config,
            view_change_rounds,
            view_change_failures,
            view_change_consecutive_failures,
            view_change_time,
            view_change_stall_time
        ) = config.take();
        let hash = H::default();
        let self_hash = hash.null_hash();
        let party_hashes = HashMap::new();
        let hash_parties = HashMap::new();

        Ok(PBFTProtoState {
            view_change_rounds: view_change_rounds,
            view_change_consecutive_failures: view_change_consecutive_failures,
            view_change_failures: view_change_failures,
            view_change_time: view_change_time,
            view_change_stall_time: view_change_stall_time,
            outbound_config: outbound_config,
            party_hashes: party_hashes,
            hash_parties: hash_parties,
            leader: PBFTLeader::None { hint: None },
            // XXX use a size hint here.  Also calculate number of
            // hashes per payload.
            pending: OperBatches::new(16),
            self_hash: self_hash,
            hash: hash
        })
    }

    fn update<P>(
        &mut self,
        _parties: &mut P,
        oper: &PBFTRoundResult<PbftRequest>
    ) -> Result<(), Self::UpdateError>
    where
        P: Parties<Types> {
        match oper {
            PBFTRoundResult::Complete {
                req: PbftRequest::View(PbftView { id })
            } => {
                let id = self.hash.wrap_hashed_bytes(id).map_err(|err| {
                    PBFTProtoStateUpdateError::BadSize { err: err }
                })?;

                if self.self_hash == id {
                    info!(target: "pbft-proto-state",
                          "we became leader of consensus pool");

                    self.leader = PBFTLeader::This;

                    Ok(())
                } else {
                    match self.hash_parties.get(&id) {
                        Some(party) => {
                            info!(target: "pbft-proto-state",
                                  "party {} became leader of consensus pool",
                                  party);

                            let stall_start = if self.pending.is_empty() {
                                None
                            } else {
                                Some(Instant::now())
                            };

                            self.leader = PBFTLeader::Other {
                                view_start: Instant::now(),
                                stall_start: stall_start,
                                nconsecutive_failures: 0,
                                nfailures: 0,
                                nrounds: 0,
                                party: party.clone()
                            };

                            Ok(())
                        }
                        None => {
                            Err(PBFTProtoStateUpdateError::BadParty { id: id })
                        }
                    }
                }
            }
            PBFTRoundResult::Complete {
                req: PbftRequest::Members(_)
            } => {
                error!(target: "pbft-proto-state",
                       "member update not yet implemented!");

                if let PBFTLeader::Other {
                    nconsecutive_failures,
                    stall_start,
                    nrounds,
                    ..
                } = &mut self.leader
                {
                    *nconsecutive_failures = 0;
                    *stall_start = None;
                    *nrounds += 1;
                }

                Ok(())
            }
            PBFTRoundResult::Complete {
                req: PbftRequest::Payload(payload)
            } => {
                let hashes = payload_hashes(&self.hash, payload).map_err(
                    |err| match err {
                        PBFTBatchError::Hash { err } => {
                            PBFTProtoStateUpdateError::BadSize { err: err }
                        }
                        PBFTBatchError::BadSize { size } => {
                            PBFTProtoStateUpdateError::BadPayload { size: size }
                        }
                    }
                )?;

                self.pending.clear_hashes(hashes.iter());

                if let PBFTLeader::Other {
                    nconsecutive_failures,
                    stall_start,
                    nrounds,
                    ..
                } = &mut self.leader
                {
                    *nconsecutive_failures = 0;
                    *stall_start = None;
                    *nrounds += 1;
                }

                Ok(())
            }
            PBFTRoundResult::Fail { fail: votes } => {
                if let PBFTLeader::Other {
                    nconsecutive_failures,
                    nfailures,
                    nrounds,
                    ..
                } = &mut self.leader
                {
                    *nconsecutive_failures = 0;
                    *nfailures += 1;
                    *nrounds += 1;
                }

                self.update_leader_hint(votes)
            }
        }
    }
}

impl<H, Types> ProtoStateRound<Types, PBFTProtoTypes>
    for PBFTProtoState<H, Types::PartyID>
where
    H: Default + HashAlgo,
    H::HashID: Clone + Display + Eq + Hash,
    Types: PartyTypes + RoundPartyIdxTypes<PartyRoundIdx = OutboundPartyIdx>,
    Types::RoundID: From<u128> + Into<u128>
{
    type CreateRoundError = PBFTRoundStateCreateError<Types::PartyID>;
    type Info = PBFTRoundInfo<OutboundPartyIdx>;
    type Round = PBFTRoundState<H::HashID, PbftRequest>;

    fn create_round(
        &mut self,
        parties: &PartyRoundIDMap<Types>
    ) -> Result<
        (
            Self::Round,
            PBFTRoundInfo<OutboundPartyIdx>,
            PBFTOutbound<Types::RoundID>,
            Option<Instant>
        ),
        PBFTRoundStateCreateError<Types::PartyID>
    > {
        let nparties = self.nparties();
        let mut out =
            PBFTOutbound::create(nparties - 1, self.outbound_config.clone());

        match &self.leader {
            // We're not the leader; don't set up any initial request,
            // unless one of the conditions for a view change is met.
            PBFTLeader::Other {
                nconsecutive_failures,
                nfailures,
                nrounds,
                stall_start,
                view_start,
                party: leader
            } => match parties.party_idx(leader) {
                Some(id) => {
                    let id: usize = id.clone().into();
                    let id = OutboundPartyIdx::from(id + 1);
                    let info = PBFTRoundInfo::Other { party: id.clone() };
                    let now = Instant::now();
                    let view_deadline = self
                        .view_change_time
                        .map(|duration| *view_start + duration);
                    let stall_deadline =
                        self.view_change_stall_time.and_then(|duration| {
                            stall_start.map(|start| start + duration)
                        });
                    let deadline = stall_deadline.map_or(
                        view_deadline,
                        |stall_deadline| {
                            view_deadline.map(|view_deadline| {
                                view_deadline.min(stall_deadline)
                            })
                        }
                    );
                    let round = if self.view_change_rounds <= *nrounds ||
                        self.view_change_failures <= *nfailures ||
                        self.view_change_consecutive_failures <=
                            *nconsecutive_failures ||
                        deadline.is_some_and(|deadline| deadline <= now)
                    {
                        // We've hit one of the view change conditions.
                        debug!(target: "pbft-proto-state",
                               "proposing view change");

                        // ISSUE #4: this needs a better mechanism
                        // for picking a leader.
                        let parties: Vec<&H::HashID> = self
                            .party_hashes
                            .iter()
                            .filter(|(party, _)| *party != leader)
                            .map(|(_, hash)| hash)
                            .collect();
                        let idx = (random::<usize>() % parties.len()) + 1;

                        let hash = if idx == 0 {
                            &self.self_hash
                        } else {
                            parties[idx - 1]
                        };

                        let req = PbftRequest::view_change(hash);

                        PBFTRoundState::with_req(&mut out, nparties, req)
                    } else {
                        // No view change.
                        PBFTRoundState::new(
                            nparties,
                            deadline,
                            self.self_hash.clone()
                        )
                    };

                    Ok((round, info, out, deadline))
                }
                None => Err(PBFTRoundStateCreateError::BadParty {
                    party: leader.clone()
                })
            },
            PBFTLeader::This => {
                let info = PBFTRoundInfo::This;
                let round = match self.pending.get_batch() {
                    Some(req) => {
                        debug!(target: "pbft-proto-state",
                               "we are the leader, generating regular round");

                        PBFTRoundState::with_req(&mut out, nparties, req)
                    }
                    None => {
                        debug!(target: "pbft-proto-state",
                               "we are the leader, no batches to submit");

                        PBFTRoundState::new(
                            nparties,
                            None,
                            self.self_hash.clone()
                        )
                    }
                };

                Ok((round, info, out, None))
            }
            // There is no leader, but we have a hint proposing ourself.
            PBFTLeader::None {
                hint: Some(PBFTLeaderHint::This)
            } => {
                debug!(target: "pbft-proto-state",
                       "no one is the leader, hint proposes ourself");

                let req = PbftRequest::view_change(&self.self_hash);
                let round = PBFTRoundState::with_req(&mut out, nparties, req);
                let info = PBFTRoundInfo::None;

                Ok((round, info, out, None))
            }
            // There is no leader, but we have a hint proposing someone else.
            PBFTLeader::None {
                hint: Some(PBFTLeaderHint::Other { party })
            } => {
                let info = PBFTRoundInfo::None;

                debug!(target: "pbft-proto-state",
                       "no one is the leader, hint proposes {}",
                       party);

                match self.party_hashes.get(party) {
                    Some(hash) => {
                        let req = PbftRequest::view_change(hash);
                        let round =
                            PBFTRoundState::with_req(&mut out, nparties, req);

                        Ok((round, info, out, None))
                    }
                    // This shouldn't ever happen.
                    None => Err(PBFTRoundStateCreateError::BadHint {
                        party: party.clone()
                    })
                }
            }
            // There is no leader: propose ourselves.
            PBFTLeader::None { hint: None } => {
                debug!(target: "pbft-proto-state",
                       "no one is the leader, generating view change");

                // ISSUE #4: this needs a better mechanism for picking
                // a leader.
                let parties: Vec<&H::HashID> =
                    self.party_hashes.values().collect();
                let idx = (random::<usize>() % parties.len()) + 1;
                let info = PBFTRoundInfo::None;

                let hash = if idx == 0 {
                    &self.self_hash
                } else {
                    parties[idx - 1]
                };

                let req = PbftRequest::view_change(hash);
                let round = PBFTRoundState::with_req(&mut out, nparties, req);

                Ok((round, info, out, None))
            }
        }
    }
}

impl<Out, H, PartyID> RoundStateNotify<Out, PBFTProtoState<H, PartyID>>
    for PBFTRoundState<H::HashID, PbftRequest>
where
    PartyID: Clone + Display + Eq + Hash + From<usize> + Into<usize>,
    Out: PBFTOutboundSend<PbftRequest>,
    H: Default + HashAlgo,
    H::HashID: Clone + Display + Eq + Hash
{
    type NotifyError = Infallible;

    fn notify_update(
        mut self,
        state: &mut PBFTProtoState<H, PartyID>,
        out: &mut Out
    ) -> Result<Self, Self::NotifyError> {
        // We can only generate a request if we're the leader.
        if matches!(&state.leader, PBFTLeader::This) {
            // We can only generate a request in the prepare state.
            if let PBFTRoundState::Prepare { prepare } = &mut self {
                // We can only generate a request if we haven't already voted.
                if let PreparedReq::None { .. } = &prepare.prepared {
                    // We haven't prepared anything yet; try to generate a
                    // request.
                    let nparties = prepare.prepare_voted.len();

                    if let Some(req) = state.pending.get_batch::<PbftRequest>()
                    {
                        debug!(target: "pbft",
                               "updating round with our prepare vote for {}",
                               req);

                        // We generated a request, cast our vote and
                        // send it.
                        match prepare.prepare_votes.entry(req.clone()) {
                            Entry::Vacant(ent) => {
                                let mut votes = bitvec![0; nparties];

                                votes.set(0, true);

                                ent.insert(votes);
                            }
                            Entry::Occupied(mut votes) => {
                                votes.get_mut().set(0, true);
                            }
                        }

                        out.send_prepare(&req);
                        prepare.prepare_remaining -= 1;
                        prepare.prepare_lead = prepare.prepare_lead.max(1);
                        prepare.prepare_voted.set(0, true);
                        prepare.prepared = PreparedReq::Prepared { req: req };

                        debug!(target: "pbft",
                               concat!("prepare vote recorded, {} ",
                                       "remaining, lead has {}"),
                               prepare.prepare_remaining, prepare.prepare_lead);
                    }
                }
            }
        }

        Ok(self)
    }
}

impl<H, Out> RoundState<Out> for PBFTRoundState<H, PbftRequest>
where
    Out: PBFTOutboundSend<PbftRequest>,
    H: HashID
{
    fn time_update(
        mut self,
        out: &mut Out
    ) -> (Self, Option<Instant>) {
        let deadline = if let PBFTRoundState::Prepare { prepare } = &mut self {
            if let PreparedReq::None {
                deadline: Some(deadline),
                leader_vote
            } = &prepare.prepared
            {
                if *deadline <= Instant::now() {
                    debug!(target: "pbft-proto-state",
                           "deadline has expired; proposing view change");

                    let req = PbftRequest::view_change(leader_vote);
                    let nparties = prepare.prepare_voted.len();

                    debug!(target: "pbft",
                           "updating round with our prepare vote for {}",
                           req);

                    match prepare.prepare_votes.entry(req.clone()) {
                        Entry::Vacant(ent) => {
                            let mut votes = bitvec![0; nparties];

                            votes.set(0, true);

                            ent.insert(votes);
                        }
                        Entry::Occupied(mut votes) => {
                            votes.get_mut().set(0, true);
                        }
                    }

                    prepare.prepare_voted.set(0, true);
                    prepare.prepare_remaining -= 1;
                    prepare.prepare_lead = prepare.prepare_lead.max(1);
                    out.send_prepare(&req);
                    prepare.prepared = PreparedReq::Prepared { req: req };

                    debug!(target: "pbft",
                           concat!("prepare vote recorded, {} ",
                                   "remaining, lead has {}"),
                           prepare.prepare_remaining, prepare.prepare_lead);

                    None
                } else {
                    trace!(target: "pbft-round-state",
                           "deadline not passed; ignoring time update");

                    Some(*deadline)
                }
            } else {
                trace!(target: "pbft-round-state",
                       "request already prepared; ignoring time update");

                None
            }
        } else {
            trace!(target: "pbft-round-state",
                   "round is already beyond prepare; ignoring time update");

            None
        };

        (self, deadline)
    }
}

impl<H, Types>
    RoundStateRecv<
        Types,
        PBFTProtoTypes,
        PBFTRoundResult<PbftRequest>,
        PBFTRoundInfo<OutboundPartyIdx>
    > for PBFTRoundState<H, PbftRequest>
where
    H: HashID,
    Types: PartyTypes + RoundPartyIdxTypes<PartyRoundIdx = OutboundPartyIdx>,
    Types::RoundID: From<u128> + Into<u128>
{
    fn recv(
        self,
        out: &mut PBFTOutbound<Types::RoundID>,
        info: &PBFTRoundInfo<OutboundPartyIdx>,
        round: &Types::RoundID,
        party: &OutboundPartyIdx,
        msg: PbftContent
    ) -> RoundStateUpdate<Self, PBFTRoundResult<PbftRequest>> {
        match msg {
            PbftContent::UpdateAck(PbftUpdateAck { update, .. }) |
            PbftContent::Update(update) => match update {
                PbftStateUpdate::Prepare(req) => {
                    let ignore_leader = matches!(req, PbftRequest::View(_));

                    self.prepare(out, round, info, party, req, ignore_leader)
                }
                PbftStateUpdate::Commit(req) => {
                    let ignore_leader = matches!(req, PbftRequest::View(_));

                    self.commit(out, round, info, party, req, ignore_leader)
                }
                PbftStateUpdate::Complete(req) => {
                    self.complete(out, round, info, party, req)
                }
                PbftStateUpdate::Fail(_) => self.fail(out, round, party)
            },
            _ => RoundStateUpdate::Pending { pending: self }
        }
    }
}

impl<Party> Display for PBFTRoundStateCreateError<Party>
where
    Party: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            PBFTRoundStateCreateError::BadParty { party } => {
                write!(f, "unknown party {}", party)
            }
            PBFTRoundStateCreateError::BadHint { party } => {
                write!(f, "unknown party {} in leader hint", party)
            }
        }
    }
}

impl<Parties, Encode> Display for PBFTProtoStateCreateError<Parties, Encode>
where
    Parties: Display,
    Encode: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            PBFTProtoStateCreateError::Parties { err } => err.fmt(f),
            PBFTProtoStateCreateError::Encode { err } => err.fmt(f)
        }
    }
}

impl Display for PBFTBatchError {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            PBFTBatchError::Hash { err } => write!(f, "{}", err),
            PBFTBatchError::BadSize { size } => {
                write!(f, "bad payload size {}", size)
            }
        }
    }
}

impl<H> Display for PBFTProtoStateUpdateError<H>
where
    H: Display + HashID
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            PBFTProtoStateUpdateError::BadSize { err } => write!(f, "{}", err),
            PBFTProtoStateUpdateError::BadParty { id } => {
                write!(f, "bad party hash: {}", id)
            }
            PBFTProtoStateUpdateError::BadPayload { size } => {
                write!(f, "bad payload size {}", size)
            }
        }
    }
}

#[cfg(test)]
use std::fmt::Debug;

#[cfg(test)]
use crate::init;

#[cfg(test)]
struct TestOutbound<Req: Clone> {
    prepare: Option<Req>,
    commit: Option<Req>,
    complete: Option<Req>,
    fail: bool
}

#[cfg(test)]
impl<Req: Clone> TestOutbound<Req> {
    #[inline]
    fn new() -> Self {
        TestOutbound {
            prepare: None,
            commit: None,
            complete: None,
            fail: false
        }
    }
}

#[cfg(test)]
impl<Req: Clone> PBFTOutboundSend<Req> for TestOutbound<Req> {
    #[inline]
    fn send_prepare(
        &mut self,
        req: &Req
    ) {
        assert!(self.prepare.is_none());

        self.prepare = Some(req.clone())
    }

    #[inline]
    fn send_commit(
        &mut self,
        req: &Req
    ) {
        assert!(self.commit.is_none());

        self.commit = Some(req.clone())
    }

    #[inline]
    fn send_complete(
        &mut self,
        req: &Req
    ) {
        assert!(self.complete.is_none());

        self.complete = Some(req.clone())
    }

    #[inline]
    fn send_fail(&mut self) {
        self.fail = true
    }
}

#[cfg(test)]
fn check_votes<Req>(
    votes: &HashMap<Req, BitVec>,
    voted: &BitVec,
    lead: usize,
    expected: &HashMap<usize, Req>
) where
    Req: Clone + Debug + Display + Eq + Hash {
    let mut party_votes = HashMap::with_capacity(voted.len());
    let mut lead_votes = 0;

    for (req, req_votes) in votes {
        for i in req_votes.iter_ones() {
            assert!(!party_votes.contains_key(&i));
            assert!(voted[i]);

            lead_votes = lead_votes.max(req_votes.count_ones());
            party_votes.insert(i, req.clone());
        }
    }

    assert_eq!(&party_votes, expected);
    assert_eq!(lead, lead_votes);
}

#[cfg(test)]
fn check_consistency<Req: Clone>(
    state: &RoundStateUpdate<PBFTRoundState<SHA3ID, Req>, PBFTRoundResult<Req>>,
    outbound: &TestOutbound<Req>,
    prepare_votes: &HashMap<usize, Req>,
    commit_votes: &HashMap<usize, Req>,
    _self_party: usize
) where
    Req: Clone + Debug + Display + Eq + Hash {
    match state {
        RoundStateUpdate::Pending {
            pending: PBFTRoundState::Prepare { prepare }
        } => {
            check_votes(
                &prepare.prepare_votes,
                &prepare.prepare_voted,
                prepare.prepare_lead,
                &prepare_votes
            );
            check_votes(
                &prepare.commit_votes,
                &prepare.commit_voted,
                prepare.commit_lead,
                &commit_votes
            );

            assert_eq!(
                prepare.prepare_remaining,
                prepare.prepare_voted.len() -
                    prepare.prepare_voted.count_ones()
            );
            assert_eq!(
                prepare.commit_remaining,
                prepare.commit_voted.len() - prepare.commit_voted.count_ones()
            );

            match (&outbound.prepare, &prepare.prepared) {
                (None, PreparedReq::Prepared { .. }) => {
                    panic!("prepare has value, but no outbound")
                }
                (Some(_), PreparedReq::None { .. }) => {
                    panic!("outbound has value, but no prepare")
                }
                (Some(a), PreparedReq::Prepared { req: b }) => assert_eq!(a, b),
                _ => {}
            }
        }
        RoundStateUpdate::Pending {
            pending: PBFTRoundState::Commit { commit }
        } => {
            check_votes(
                &commit.commit_votes,
                &commit.commit_voted,
                commit.commit_lead,
                &commit_votes
            );

            assert_eq!(
                commit.commit_remaining,
                commit.commit_voted.len() - commit.commit_voted.count_ones()
            );

            match (&outbound.commit, &commit.commit) {
                (None, Some(_)) => panic!("commit has value, but no outbound"),
                (Some(_), None) => panic!("outbound has value, but no commit"),
                (Some(a), Some(b)) => assert_eq!(a, b),
                _ => {}
            }
        }
        RoundStateUpdate::Resolved {
            resolved: PBFTRoundResult::Complete { req }
        } => match &outbound.complete {
            None => panic!("inconsistent state and outbound"),
            Some(out) => assert_eq!(req, out)
        },
        RoundStateUpdate::Resolved {
            resolved: PBFTRoundResult::Fail { .. }
        } => {
            assert!(outbound.fail);
        }
    }
}

#[cfg(test)]
const TOLERANCES: [(usize, usize); 102] = [
    (4, 1),
    (5, 1),
    (6, 1),
    (7, 2),
    (8, 2),
    (9, 2),
    (10, 3),
    (11, 3),
    (12, 3),
    (13, 4),
    (14, 4),
    (15, 4),
    (16, 5),
    (17, 5),
    (18, 5),
    (19, 6),
    (20, 6),
    (21, 6),
    (22, 7),
    (23, 7),
    (24, 7),
    (25, 8),
    (26, 8),
    (27, 8),
    (28, 9),
    (29, 9),
    (30, 9),
    (31, 10),
    (32, 10),
    (33, 10),
    (34, 11),
    (35, 11),
    (36, 11),
    (37, 12),
    (38, 12),
    (39, 12),
    (40, 13),
    (41, 13),
    (42, 13),
    (43, 14),
    (44, 14),
    (45, 14),
    (46, 15),
    (47, 15),
    (48, 15),
    (49, 16),
    (50, 16),
    (51, 16),
    (52, 17),
    (53, 17),
    (54, 17),
    (55, 18),
    (56, 18),
    (57, 18),
    (58, 19),
    (59, 19),
    (60, 19),
    (61, 20),
    (62, 20),
    (63, 20),
    (64, 21),
    (65, 21),
    (66, 21),
    (67, 22),
    (68, 22),
    (69, 22),
    (70, 23),
    (71, 23),
    (72, 23),
    (73, 24),
    (74, 24),
    (75, 24),
    (76, 25),
    (77, 25),
    (78, 25),
    (79, 26),
    (80, 26),
    (81, 26),
    (82, 27),
    (83, 27),
    (84, 27),
    (85, 28),
    (86, 28),
    (87, 28),
    (88, 29),
    (89, 29),
    (90, 29),
    (91, 30),
    (92, 30),
    (93, 30),
    (94, 31),
    (95, 31),
    (96, 31),
    (97, 32),
    (98, 32),
    (99, 32),
    (100, 33),
    (101, 33),
    (102, 33),
    (103, 34),
    (104, 34),
    (105, 34)
];

#[cfg(test)]
use constellation_common::hashid::SHA3Algo;
#[cfg(test)]
use constellation_common::hashid::SHA3ID;

#[test]
fn test_new() {
    init();

    let hash = SHA3Algo::wrap_hashed_bytes(&SHA3Algo::default(), &[0; 64])
        .expect("expected success");

    for (nparties, nfaults) in TOLERANCES {
        let state: PBFTRoundState<SHA3ID, usize> =
            PBFTRoundState::new(nparties, None, hash.clone());

        match state {
            PBFTRoundState::Prepare { prepare } => {
                let quorum = nparties - nfaults;

                assert!(quorum >= (2 * nfaults) + 1);
                assert_eq!(prepare.quorum, quorum);
                assert!(matches!(prepare.prepared, PreparedReq::None { .. }));
                assert!(prepare.prepare_votes.is_empty());
                assert_eq!(prepare.prepare_voted.count_ones(), 0);
                assert_eq!(prepare.prepare_remaining, nparties);
                assert_eq!(prepare.prepare_lead, 0);
                assert!(prepare.commit_votes.is_empty());
                assert_eq!(prepare.commit_voted.count_ones(), 0);
                assert_eq!(prepare.commit_remaining, nparties);
                assert_eq!(prepare.commit_lead, 0);
            }
            _ => panic!("Expected prepare state")
        }
    }
}

#[test]
fn test_leader() {
    init();

    for (nparties, nfaults) in TOLERANCES {
        let mut outbound = TestOutbound::new();
        let proposal = 2;
        let state: PBFTRoundState<SHA3ID, usize> =
            PBFTRoundState::with_req(&mut outbound, nparties, proposal);
        let expect_prepare = [(0, proposal)].iter().cloned().collect();

        match &state {
            PBFTRoundState::Prepare { prepare } => {
                let quorum = nparties - nfaults;

                assert!(quorum >= (2 * nfaults) + 1);
                assert_eq!(prepare.quorum, quorum);

                assert_eq!(
                    prepare.prepared,
                    PreparedReq::Prepared { req: proposal }
                );
                assert_eq!(prepare.prepare_voted.count_ones(), 1);
                assert_eq!(prepare.prepare_remaining, nparties - 1);
                assert_eq!(prepare.prepare_lead, 1);
                assert_eq!(prepare.prepare_votes.len(), 1);

                let votes = prepare
                    .prepare_votes
                    .get(&proposal)
                    .expect("Expected some");

                assert_eq!(votes.count_ones(), 1);
                assert!(votes[0]);

                assert!(prepare.commit_votes.is_empty());
                assert_eq!(prepare.commit_voted.count_ones(), 0);
                assert_eq!(prepare.commit_remaining, nparties);
                assert_eq!(prepare.commit_lead, 0);
            }
            _ => panic!("Expected prepare state")
        }

        check_consistency(
            &RoundStateUpdate::Pending { pending: state },
            &outbound,
            &expect_prepare,
            &HashMap::new(),
            0
        );
    }
}

#[cfg(test)]
enum ConsensusTestOp {
    Prepare { req: usize, party: usize },
    Commit { req: usize, party: usize },
    Complete { req: usize, party: usize },
    Fail { party: usize }
}

#[cfg(test)]
fn consensus_test<F>(
    init_proposal: Option<usize>,
    leader: &PBFTRoundInfo<OutboundPartyIdx>,
    expect_prepare: &[(usize, usize)],
    expect_commit: &[(usize, usize)],
    ops: &[ConsensusTestOp],
    check: F
) where
    F: FnOnce(
        RoundStateUpdate<PBFTRoundState<SHA3ID, usize>, PBFTRoundResult<usize>>
    ) {
    init();

    let round = 1337;
    let nparties = 10;
    let mut outbound = TestOutbound::new();
    let state: PBFTRoundState<SHA3ID, usize> = match init_proposal {
        Some(proposal) => {
            PBFTRoundState::with_req(&mut outbound, nparties, proposal)
        }
        None => {
            let hash =
                SHA3Algo::wrap_hashed_bytes(&SHA3Algo::default(), &[0; 64])
                    .expect("expected success");

            PBFTRoundState::new(nparties, None, hash)
        }
    };
    let expect_prepare = expect_prepare.iter().cloned().collect();
    let expect_commit = expect_commit.iter().cloned().collect();
    let mut update = RoundStateUpdate::Pending { pending: state };

    for op in ops {
        update = match update {
            RoundStateUpdate::Pending { pending } => match op {
                ConsensusTestOp::Prepare { req, party } => {
                    let party = party - 1;

                    pending.prepare(
                        &mut outbound,
                        &round,
                        leader,
                        &OutboundPartyIdx::from(party),
                        *req,
                        false
                    )
                }
                ConsensusTestOp::Commit { req, party } => {
                    let party = party - 1;

                    pending.commit(
                        &mut outbound,
                        &round,
                        leader,
                        &OutboundPartyIdx::from(party),
                        *req,
                        false
                    )
                }
                ConsensusTestOp::Complete { req, party } => {
                    let party = party - 1;

                    pending.complete(
                        &mut outbound,
                        &round,
                        leader,
                        &OutboundPartyIdx::from(party),
                        *req
                    )
                }
                ConsensusTestOp::Fail { party } => {
                    let party = party - 1;

                    pending.fail(&mut outbound, &round, &party)
                }
            },
            _ => panic!("protocol terminated unexpectedly")
        }
    }

    check_consistency(
        &update,
        &outbound,
        &expect_prepare,
        &expect_commit,
        SELF_PARTY
    );
    check(update);
}

#[test]
fn test_withreq_handle_prepare_nolead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[ConsensusTestOp::Prepare {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_selflead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[ConsensusTestOp::Prepare {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_nonlead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[ConsensusTestOp::Prepare {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_lead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[ConsensusTestOp::Prepare {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_nonlead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[],
        &[ConsensusTestOp::Prepare {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_lead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[ConsensusTestOp::Prepare {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_nolead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_selflead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_nonlead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_lead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_nonlead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_lead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_nolead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_selflead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_nonlead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_lead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_nonlead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_lead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_nolead_consistent_commit() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_selflead_consistent_commit() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_nonlead_consistent_commit() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_lead_consistent_commit() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_nonlead_consistent_commit() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_lead_consistent_commit() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

// ISSUE #5: We should probably discard inconsistent commits.

#[test]
fn test_withreq_handle_prepare_nolead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, inconsistent)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_selflead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, inconsistent)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_nonlead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, inconsistent)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_lead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, inconsistent)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_nonlead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, inconsistent)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_lead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, inconsistent)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_nolead_superceding_complete() {
    let party = 1;
    let proposal = 2;
    let superceding = 3;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, superceding)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: superceding,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_selflead_superceding_complete() {
    let party = 1;
    let proposal = 2;
    let superceding = 3;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, superceding)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: superceding,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_nonlead_superceding_complete() {
    let party = 1;
    let proposal = 2;
    let superceding = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, superceding)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: superceding,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_lead_superceding_complete() {
    let party = 1;
    let proposal = 2;
    let superceding = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, superceding)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: superceding,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_nonlead_superceding_complete() {
    let party = 1;
    let proposal = 2;
    let superceding = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, superceding)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: superceding,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_lead_superceding_complete() {
    let party = 1;
    let proposal = 2;
    let superceding = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, superceding)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: superceding,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_nolead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_selflead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_nonlead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_prepare_lead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_nonlead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_prepare_lead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nolead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[ConsensusTestOp::Commit {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_selflead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[ConsensusTestOp::Commit {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nonlead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[ConsensusTestOp::Commit {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_lead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[ConsensusTestOp::Commit {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_nonlead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[ConsensusTestOp::Commit {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_lead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[ConsensusTestOp::Commit {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nolead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_selflead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nonlead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_lead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_nonlead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_lead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nolead_consistent_prepare() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_selflead_consistent_prepare() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nonlead_consistent_prepare() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_lead_consistent_prepare() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_nonlead_consistent_prepare() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_lead_consistent_prepare() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nolead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_selflead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nonlead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_lead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_nonlead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_lead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nolead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_selflead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nonlead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_lead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_nonlead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_lead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nolead_superceding_complete() {
    let party = 1;
    let proposal = 2;
    let superceding = 3;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: superceding,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_selflead_superceding_complete() {
    let party = 1;
    let proposal = 2;
    let superceding = 3;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: superceding,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nonlead_superceding_complete() {
    let party = 1;
    let proposal = 2;
    let superceding = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: superceding,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_lead_superceding_complete() {
    let party = 1;
    let proposal = 2;
    let superceding = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: superceding,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_nonlead_superceding_complete() {
    let party = 1;
    let proposal = 2;
    let superceding = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: superceding,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_lead_superceding_complete() {
    let party = 1;
    let proposal = 2;
    let superceding = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: superceding,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nolead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_selflead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_nonlead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_commit_lead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_nonlead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_commit_lead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nolead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[ConsensusTestOp::Complete {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_selflead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[ConsensusTestOp::Complete {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nonlead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[ConsensusTestOp::Complete {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_lead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[ConsensusTestOp::Complete {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_nonlead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[ConsensusTestOp::Complete {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_lead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[ConsensusTestOp::Complete {
            req: proposal,
            party: party
        }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nolead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_selflead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nonlead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_lead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_nonlead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_lead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nolead_consistent_prepare() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_selflead_consistent_prepare() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nonlead_consistent_prepare() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_lead_consistent_prepare() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_nonlead_consistent_prepare() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_lead_consistent_prepare() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nolead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_selflead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nonlead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_lead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_nonlead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_lead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nolead_consistent_commit() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_selflead_consistent_commit() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nonlead_consistent_commit() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_lead_consistent_commit() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_nonlead_consistent_commit() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_lead_consistent_commit() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nolead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_selflead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nonlead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_lead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_nonlead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_lead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nolead_inconsistent_complete() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_selflead_inconsistent_complete() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nonlead_inconsistent_complete() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_lead_inconsistent_complete() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_nonlead_inconsistent_complete() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_lead_inconsistent_complete() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nolead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_selflead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_nonlead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_complete_lead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_nonlead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[(party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_complete_lead_fail() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal), (party, proposal)],
        &[(party, proposal)],
        &[
            ConsensusTestOp::Complete {
                req: proposal,
                party: party
            },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_nolead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[ConsensusTestOp::Fail { party: party }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_selflead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[ConsensusTestOp::Fail { party: party }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_nonlead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[ConsensusTestOp::Fail { party: party }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_lead() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[ConsensusTestOp::Fail { party: party }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_fail_nonlead() {
    let party = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[],
        &[],
        &[ConsensusTestOp::Fail { party: party }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_fail_lead() {
    let party = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[],
        &[],
        &[ConsensusTestOp::Fail { party: party }],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_nolead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_selflead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_nonlead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_lead_idempotent() {
    let party = 1;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_fail_nonlead_idempotent() {
    let party = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_fail_lead_idempotent() {
    let party = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Fail { party: party }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_nolead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_selflead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_nonlead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_lead_inconsistent_prepare() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_fail_nonlead_inconsistent_prepare() {
    let party = 1;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_fail_lead_inconsistent_prepare() {
    let party = 1;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Prepare {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_nolead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_selflead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_nonlead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_lead_inconsistent_commit() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_fail_nonlead_inconsistent_commit() {
    let party = 1;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_fail_lead_inconsistent_commit() {
    let party = 1;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_nolead_inconsistent_complete() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_selflead_inconsistent_complete() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_nonlead_inconsistent_complete() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_handle_fail_lead_inconsistent_complete() {
    let party = 1;
    let proposal = 2;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::Prepared { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_fail_nonlead_inconsistent_complete() {
    let party = 1;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(2)
    };

    consensus_test(
        None,
        &leader,
        &[],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_empty_handle_fail_lead_inconsistent_complete() {
    let party = 1;
    let inconsistent = 3;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[],
        &[],
        &[
            ConsensusTestOp::Fail { party: party },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: party
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Prepare {
                        prepare:
                            PrepareState {
                                prepared: PreparedReq::None { .. },
                                ..
                            }
                    }
            } => {}
            _ => panic!("Expected prepare state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_basic_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_basic_selflead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_basic_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_basic_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_basic_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_basic_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_initial_nolead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(overridden),
        &leader,
        &[
            (SELF_PARTY, overridden),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_initial_selflead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(overridden),
        &leader,
        &[
            (SELF_PARTY, overridden),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_initial_nonlead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(overridden),
        &leader,
        &[
            (SELF_PARTY, overridden),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_initial_lead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(overridden),
        &leader,
        &[
            (SELF_PARTY, overridden),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_prepare_nolead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_prepare_selflead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_prepare_nonlead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_prepare_lead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, overridden),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_prepare_nonlead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_prepare_lead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, overridden),
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[(SELF_PARTY, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_prepare_lead_wins() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, overridden),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_prepare_lead_self_wins() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(7)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, overridden),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_commit_nolead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, overridden),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (2, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_commit_selflead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, overridden)],
        &[
            ConsensusTestOp::Commit {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_commit_nonlead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, overridden)],
        &[
            ConsensusTestOp::Commit {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_commit_lead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, overridden),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (2, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_commit_nonlead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[(1, overridden)],
        &[
            ConsensusTestOp::Commit {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_commit_lead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, overridden),
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[(SELF_PARTY, overridden), (1, overridden)],
        &[
            ConsensusTestOp::Commit {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_commit_lead_wins() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, overridden),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[(SELF_PARTY, proposal), (2, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_commit_lead_self_wins() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(7)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, overridden),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (2, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_complete_nolead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, overridden),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (2, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_complete_selflead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, overridden)],
        &[
            ConsensusTestOp::Complete {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_complete_nonlead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, overridden)],
        &[
            ConsensusTestOp::Complete {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_complete_lead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, overridden),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (2, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_complete_nonlead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[(1, overridden)],
        &[
            ConsensusTestOp::Complete {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_complete_lead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, overridden),
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[(SELF_PARTY, overridden), (1, overridden)],
        &[
            ConsensusTestOp::Complete {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_complete_lead_wins() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, overridden),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[(SELF_PARTY, proposal), (2, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_complete_lead_self_wins() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(7)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, overridden),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (2, overridden)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_fail_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_fail_selflead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_fail_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_finish_prepare_override_fail_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_fail_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_fail_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_fail_lead_wins() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_empty_finish_prepare_override_fail_lead_self_wins() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(7)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_withreq_deadlock_prepare_nolead() {
    let a = 1;
    let b = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, b),
            (5, b),
            (6, b),
            (7, b)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: b, party: 4 },
            ConsensusTestOp::Prepare { req: b, party: 5 },
            ConsensusTestOp::Prepare { req: b, party: 6 },
            ConsensusTestOp::Prepare { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_deadlock_prepare_selflead() {
    let a = 1;
    let b = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, b),
            (5, b),
            (6, b),
            (7, b)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: b, party: 4 },
            ConsensusTestOp::Prepare { req: b, party: 5 },
            ConsensusTestOp::Prepare { req: b, party: 6 },
            ConsensusTestOp::Prepare { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_deadlock_prepare_nonlead() {
    let a = 1;
    let b = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, b),
            (5, b),
            (6, b),
            (7, b)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: b, party: 4 },
            ConsensusTestOp::Prepare { req: b, party: 5 },
            ConsensusTestOp::Prepare { req: b, party: 6 },
            ConsensusTestOp::Prepare { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_deadlock_prepare_lead() {
    let a = 1;
    let b = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, b),
            (5, b),
            (6, b),
            (7, b)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: b, party: 4 },
            ConsensusTestOp::Prepare { req: b, party: 5 },
            ConsensusTestOp::Prepare { req: b, party: 6 },
            ConsensusTestOp::Prepare { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_empty_deadlock_prepare_nonlead() {
    let a = 1;
    let b = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, b),
            (6, b),
            (7, b),
            (8, b)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: b, party: 5 },
            ConsensusTestOp::Prepare { req: b, party: 6 },
            ConsensusTestOp::Prepare { req: b, party: 7 },
            ConsensusTestOp::Prepare { req: b, party: 8 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_empty_deadlock_prepare_lead() {
    let a = 1;
    let b = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(7)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, b),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, b),
            (6, b),
            (7, b)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: b, party: 5 },
            ConsensusTestOp::Prepare { req: b, party: 6 },
            ConsensusTestOp::Prepare { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_all_fail_prepare_nolead() {
    let proposal = 0;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_all_fail_prepare_selflead() {
    let proposal = 0;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_all_fail_prepare_nonlead() {
    let proposal = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_all_fail_prepare_lead() {
    let proposal = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_empty_all_fail_prepare_nonlead() {
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_empty_all_fail_prepare_lead() {
    let proposal = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, proposal)],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_fail_prepare_nolead() {
    let proposal = 0;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Fail { party: 8 },
            ConsensusTestOp::Fail { party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_fail_prepare_selflead() {
    let proposal = 0;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Fail { party: 8 },
            ConsensusTestOp::Fail { party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_fail_prepare_lead() {
    let proposal = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Fail { party: 8 },
            ConsensusTestOp::Fail { party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_empty_fail_prepare_nonlead() {
    let proposal = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Fail { party: 8 },
            ConsensusTestOp::Fail { party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_empty_fail_prepare_lead() {
    let proposal = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Fail { party: 8 },
            ConsensusTestOp::Fail { party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_doomed_prepare_nolead() {
    let a = 1;
    let b = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(a),
        &leader,
        &[(SELF_PARTY, a), (4, b)],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Prepare { req: b, party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_doomed_prepare_selflead() {
    let a = 1;
    let b = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(a),
        &leader,
        &[(SELF_PARTY, a), (4, b)],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Prepare { req: b, party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_doomed_prepare_nonlead() {
    let a = 1;
    let b = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(a),
        &leader,
        &[(SELF_PARTY, a), (4, b)],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Prepare { req: b, party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_withreq_doomed_prepare_lead() {
    let a = 1;
    let b = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(a),
        &leader,
        &[(SELF_PARTY, a), (4, b)],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Prepare { req: b, party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_empty_doomed_prepare_nonlead() {
    let a = 1;
    let b = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[(4, a), (4, b)],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: b, party: 5 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_empty_doomed_prepare_lead() {
    let a = 1;
    let b = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        None,
        &leader,
        &[(SELF_PARTY, b), (4, b), (5, a)],
        &[],
        &[
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Prepare { req: b, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail")
        }
    );
}

#[test]
fn test_commit_handle_commit_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_selflead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_noprepared_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_noprepared_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (9, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_idempotent_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_idempotent_selflead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_idempotent_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_idempotent_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_idempotent_noprepared_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_idempotent_noprepared_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (9, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_commit_nolead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_commit_selflead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_commit_nonlead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_commit_lead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_commit_noprepared_nolead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_commit_noprepared_lead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (9, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_consistent_complete_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_consistent_complete_selflead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_consistent_complete_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_consistent_complete_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_consistent_complete_noprepared_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_consistent_complete_noprepared_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (9, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_complete_nolead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_complete_selflead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_complete_nonlead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_complete_lead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_complete_noprepared_nolead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_complete_noprepared_lead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (9, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_fail_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_fail_selflead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_fail_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_fail_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_fail_noprepared_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_commit_inconsistent_fail_noprepared_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (9, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Fail { party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_selflead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_noprepared_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_noprepared_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (9, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_idempotent_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_idempotent_selflead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_idempotent_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_idempotent_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_idempotent_noprepared_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_idempotent_noprepared_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (9, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_inconsistent_commit_nolead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_inconsistent_commit_selflead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_inconsistent_commit_nonlead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_inconsistent_commit_lead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_inconsistent_commit_noprepared_nolead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_inconsistent_commit_noprepared_lead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (9, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_inconsistent_fail_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_inconsistent_fail_selflead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_inconsistent_fail_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_inconsistent_fail_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal), (1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_inconsistent_fail_noprepared_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(1, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_complete_inconsistent_fail_noprepared_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[(SELF_PARTY, proposal), (9, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Fail { party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_selflead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_noprepared_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_noprepared_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Fail { party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_idempotent_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_idempotent_selflead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_idempotent_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_idempotent_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_idempotent_noprepared_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_idempotent_noprepared_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Fail { party: 9 },
            ConsensusTestOp::Fail { party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_inconsistent_commit_nolead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_inconsistent_commit_selflead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_inconsistent_commit_nonlead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_inconsistent_commit_lead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_inconsistent_commit_noprepared_nolead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_inconsistent_commit_noprepared_lead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Fail { party: 9 },
            ConsensusTestOp::Commit {
                req: inconsistent,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_inconsistent_complete_nolead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_inconsistent_complete_selflead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_inconsistent_complete_nonlead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_inconsistent_complete_lead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[(SELF_PARTY, proposal)],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit:
                            CommitState {
                                commit: Some(_), ..
                            }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_inconsistent_complete_noprepared_nolead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: 1
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_commit_handle_fail_inconsistent_complete_noprepared_lead() {
    let proposal = 2;
    let inconsistent = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Fail { party: 9 },
            ConsensusTestOp::Complete {
                req: inconsistent,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Pending {
                pending:
                    PBFTRoundState::Commit {
                        commit: CommitState { commit: None, .. }
                    }
            } => {}
            _ => panic!("Expected commit state")
        }
    );
}

#[test]
fn test_finish_commit_basic_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_basic_selflead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_basic_nonlead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_basic_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(proposal),
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_basic_noprepared_nolead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_basic_noprepared_lead() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_basic_carryover() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_basic_carryover_commit() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_basic_carryover_complete() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_basic_decide_both() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_basic_decide_both_commit() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_basic_decide_both_complete() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_nolead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(overridden),
        &leader,
        &[
            (SELF_PARTY, overridden),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            (SELF_PARTY, overridden),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_selflead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(overridden),
        &leader,
        &[
            (SELF_PARTY, overridden),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            (SELF_PARTY, overridden),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_nonlead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(overridden),
        &leader,
        &[
            (SELF_PARTY, overridden),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            (SELF_PARTY, overridden),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_lead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(overridden),
        &leader,
        &[
            (SELF_PARTY, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[
            (SELF_PARTY, overridden),
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_noprepared_nolead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_noprepared_lead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            (SELF_PARTY, overridden),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (9, overridden)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 9
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_carryover() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, overridden)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_carryover_commit() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (7, overridden),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_carryover_complete() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (7, overridden),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_decide_both() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (7, overridden),
            (6, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_decide_both_commit() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (7, overridden),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_decide_both_complete() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (7, overridden),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: overridden,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_complete_lead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(overridden),
        &leader,
        &[
            (SELF_PARTY, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[
            (SELF_PARTY, overridden),
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_complete_noprepared_nolead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (8, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 8
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 8
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_complete_noprepared_lead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            (SELF_PARTY, overridden),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal),
            (9, overridden)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 9
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_complete_carryover() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, overridden)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_complete_carryover_commit() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (7, overridden),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_complete_carryover_complete() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (7, overridden),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_complete_decide_both() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (7, overridden),
            (6, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_complete_decide_both_commit() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (7, overridden),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_complete_decide_both_complete() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (7, overridden),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Complete {
                req: overridden,
                party: 7
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_fail_noprepared_lead() {
    let overridden = 0;
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (1, overridden),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal),
            (7, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: overridden,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 7
            },
            ConsensusTestOp::Fail { party: 9 },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 7
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_fail_carryover() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_fail_carryover_commit() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_fail_carryover_complete() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_fail_decide_both() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (6, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 6
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_fail_decide_both_commit() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_finish_commit_override_fail_decide_both_complete() {
    let proposal = 2;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            (SELF_PARTY, proposal),
            (1, proposal),
            (2, proposal),
            (3, proposal),
            (4, proposal),
            (5, proposal),
            (9, proposal)
        ],
        &[
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Prepare {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 1
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 2
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 3
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 4
            },
            ConsensusTestOp::Commit {
                req: proposal,
                party: 5
            },
            ConsensusTestOp::Complete {
                req: proposal,
                party: 9
            }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Complete { .. }
            } => {}
            _ => panic!("Expected complete state")
        }
    );
}

#[test]
fn test_deadlock_commit_nolead() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, b),
            (5, b),
            (6, b),
            (7, b)
        ],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Commit { req: b, party: 4 },
            ConsensusTestOp::Commit { req: b, party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_deadlock_commit_selflead() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, b),
            (5, b),
            (6, b),
            (7, b)
        ],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Commit { req: b, party: 4 },
            ConsensusTestOp::Commit { req: b, party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_deadlock_commit_nonlead() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, b),
            (5, b),
            (6, b),
            (7, b)
        ],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Commit { req: b, party: 4 },
            ConsensusTestOp::Commit { req: b, party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_deadlock_commit_lead() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, b),
            (5, b),
            (6, b),
            (7, b)
        ],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Commit { req: b, party: 4 },
            ConsensusTestOp::Commit { req: b, party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_deadlock_commit_noprepared_nolead() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[(1, a), (2, a), (3, a), (4, a), (5, a), (6, a), (7, a)],
        &[
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, b),
            (6, b),
            (7, b),
            (8, b)
        ],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Prepare { req: a, party: 7 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Commit { req: a, party: 4 },
            ConsensusTestOp::Commit { req: b, party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 },
            ConsensusTestOp::Commit { req: b, party: 8 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_deadlock_commit_noprepared_lead() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[(1, a), (2, a), (3, a), (4, a), (5, a), (6, a), (7, a)],
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, b),
            (4, b),
            (5, b),
            (6, b),
            (9, a)
        ],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Prepare { req: a, party: 7 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: b, party: 3 },
            ConsensusTestOp::Commit { req: b, party: 4 },
            ConsensusTestOp::Commit { req: b, party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Commit { req: a, party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_deadlock_commit_carryover() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, b),
            (5, b),
            (6, b),
            (7, b)
        ],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 9 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Commit { req: b, party: 4 },
            ConsensusTestOp::Commit { req: b, party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_deadlock_commit_carryover_commit() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, b),
            (4, b),
            (5, b),
            (6, b),
            (9, a)
        ],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Commit { req: a, party: 9 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: b, party: 3 },
            ConsensusTestOp::Commit { req: b, party: 4 },
            ConsensusTestOp::Commit { req: b, party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_deadlock_commit_carryover_complete() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, b),
            (4, b),
            (5, b),
            (6, b),
            (9, a)
        ],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Complete { req: a, party: 9 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: b, party: 3 },
            ConsensusTestOp::Commit { req: b, party: 4 },
            ConsensusTestOp::Commit { req: b, party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_deadlock_commit_decide_both() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, b),
            (5, b),
            (6, b),
            (7, b)
        ],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Commit { req: b, party: 4 },
            ConsensusTestOp::Commit { req: b, party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 },
            ConsensusTestOp::Prepare { req: a, party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_deadlock_commit_decide_both_commit() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, b),
            (4, b),
            (5, b),
            (6, b),
            (9, a)
        ],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: b, party: 3 },
            ConsensusTestOp::Commit { req: b, party: 4 },
            ConsensusTestOp::Commit { req: b, party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Commit { req: a, party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_deadlock_commit_decide_both_complete() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, b),
            (4, b),
            (5, b),
            (6, b),
            (9, a)
        ],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: b, party: 3 },
            ConsensusTestOp::Commit { req: b, party: 4 },
            ConsensusTestOp::Commit { req: b, party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Complete { req: a, party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_all_fail_commit_nolead() {
    let a = 0;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[(SELF_PARTY, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_all_fail_commit_selflead() {
    let a = 0;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[(SELF_PARTY, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_all_fail_commit_nonlead() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[(SELF_PARTY, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_all_fail_commit_lead() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[(SELF_PARTY, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_all_fail_commit_noprepared_nolead() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[(1, a), (2, a), (3, a), (4, a), (5, a), (6, a), (7, a)],
        &[],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Prepare { req: a, party: 7 },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_all_fail_commit_noprepared_lead() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[(1, a), (2, a), (3, a), (4, a), (5, a), (6, a), (7, a)],
        &[],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Prepare { req: a, party: 7 },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_all_fail_commit_carryover() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[(SELF_PARTY, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 9 },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_all_fail_commit_carryover_commit() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[(SELF_PARTY, a), (9, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Commit { req: a, party: 9 },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_all_fail_commit_carryover_complete() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[(SELF_PARTY, a), (9, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Complete { req: a, party: 9 },
            ConsensusTestOp::Fail { party: 1 },
            ConsensusTestOp::Fail { party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_fail_commit_nolead() {
    let a = 0;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[(SELF_PARTY, a), (1, a), (2, a), (3, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Fail { party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_fail_commit_selflead() {
    let a = 0;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[(SELF_PARTY, a), (1, a), (2, a), (3, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Fail { party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_fail_commit_nonlead() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[(SELF_PARTY, a), (1, a), (2, a), (3, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Fail { party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_fail_commit_lead() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[(SELF_PARTY, a), (1, a), (2, a), (3, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Fail { party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_fail_commit_noprepared_nolead() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[(1, a), (2, a), (3, a), (4, a), (5, a), (6, a), (7, a)],
        &[(1, a), (2, a), (3, a), (4, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Prepare { req: a, party: 7 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Commit { req: a, party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Fail { party: 8 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_fail_commit_noprepared_lead() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[(1, a), (2, a), (3, a), (4, a), (5, a), (6, a), (7, a)],
        &[(SELF_PARTY, a), (1, a), (2, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Prepare { req: a, party: 7 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_fail_commit_carryover() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[(SELF_PARTY, a), (1, a), (2, a), (3, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 9 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Commit { req: a, party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Fail { party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_fail_commit_carryover_commit() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[(SELF_PARTY, a), (1, a), (2, a), (9, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Commit { req: a, party: 9 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_fail_commit_carryover_complete() {
    let a = 0;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[(SELF_PARTY, a), (1, a), (2, a), (9, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Complete { req: a, party: 9 },
            ConsensusTestOp::Commit { req: a, party: 1 },
            ConsensusTestOp::Commit { req: a, party: 2 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_doomed_commit_nolead() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::None;

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[(SELF_PARTY, a), (7, b)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_doomed_commit_selflead() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::This;

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[(SELF_PARTY, a), (7, b)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_doomed_commit_nonlead() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[(SELF_PARTY, a), (7, b)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_doomed_commit_lead() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(1)
    };

    consensus_test(
        Some(a),
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (6, a)
        ],
        &[(SELF_PARTY, a), (7, b)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_doomed_commit_noprepared_nolead() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[(1, a), (2, a), (3, a), (4, a), (5, a), (6, a), (7, a)],
        &[(1, a), (8, b)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Prepare { req: a, party: 7 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Fail { party: 7 },
            ConsensusTestOp::Commit { req: b, party: 8 },
            ConsensusTestOp::Commit { req: a, party: 1 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_doomed_commit_noprepared_lead() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[(1, a), (2, a), (3, a), (4, a), (5, a), (6, a), (7, a)],
        &[(SELF_PARTY, a), (6, b), (9, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 6 },
            ConsensusTestOp::Prepare { req: a, party: 7 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Commit { req: a, party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_doomed_commit_carryover() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[(SELF_PARTY, a), (7, b)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Prepare { req: a, party: 9 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_doomed_commit_carryover_commit() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[(SELF_PARTY, a), (6, b), (9, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Commit { req: a, party: 9 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_doomed_commit_carryover_complete() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[(SELF_PARTY, a), (6, b), (9, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Complete { req: a, party: 9 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_doomed_commit_decide_both() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[(SELF_PARTY, a), (7, b)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Fail { party: 6 },
            ConsensusTestOp::Commit { req: b, party: 7 },
            ConsensusTestOp::Prepare { req: a, party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_doomed_commit_decide_both_commit() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[(SELF_PARTY, a), (6, b), (9, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Commit { req: a, party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}

#[test]
fn test_doomed_commit_decide_both_complete() {
    let a = 0;
    let b = 1;
    let leader = PBFTRoundInfo::Other {
        party: OutboundPartyIdx::from(9)
    };

    consensus_test(
        None,
        &leader,
        &[
            (SELF_PARTY, a),
            (1, a),
            (2, a),
            (3, a),
            (4, a),
            (5, a),
            (9, a)
        ],
        &[(SELF_PARTY, a), (6, b), (9, a)],
        &[
            ConsensusTestOp::Prepare { req: a, party: 1 },
            ConsensusTestOp::Prepare { req: a, party: 2 },
            ConsensusTestOp::Prepare { req: a, party: 3 },
            ConsensusTestOp::Prepare { req: a, party: 4 },
            ConsensusTestOp::Prepare { req: a, party: 5 },
            ConsensusTestOp::Fail { party: 3 },
            ConsensusTestOp::Fail { party: 4 },
            ConsensusTestOp::Fail { party: 5 },
            ConsensusTestOp::Commit { req: b, party: 6 },
            ConsensusTestOp::Complete { req: a, party: 9 }
        ],
        |update| match &update {
            RoundStateUpdate::Resolved {
                resolved: PBFTRoundResult::Fail { .. }
            } => {}
            _ => panic!("Expected fail state")
        }
    );
}
