// Copyright © 2024-25 The Johns Hopkins Applied Physics Laboratory LLC.
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

//! Outbound message buffer for the Castro-Liskov PBFT protocol.
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::marker::PhantomData;
use std::time::Instant;

use asn1rs::prelude::Null;
use bitvec::bitvec;
use bitvec::vec::BitVec;
use constellation_common::retry::Retry;
use constellation_consensus_common::outbound::Outbound;
use constellation_consensus_common::outbound::OutboundGroup;
use constellation_consensus_common::round::RoundMsg;
use log::debug;
use log::error;
use log::trace;
use log::warn;

use crate::config::PBFTOutboundConfig;
use crate::generated::msgs::PbftAckState;
use crate::generated::msgs::PbftContent;
use crate::generated::msgs::PbftMsg;
use crate::generated::msgs::PbftStateUpdate;
use crate::generated::msgs::PbftUpdateAck;
use crate::generated::req::PbftRequest;

/// Outbound message interface for the PBFT protocol.
pub(crate) trait PBFTOutboundSend<Req> {
    // Request to send a prepare message to all parties.
    fn send_prepare(
        &mut self,
        req: &Req
    );

    // Request to send a commit message to all parties.
    fn send_commit(
        &mut self,
        req: &Req
    );

    // Request to send complete messages from here on.
    fn send_complete(
        &mut self,
        req: &Req
    );

    // Request to send a failure message to all parties.
    fn send_fail(&mut self);
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutboundPartyIdx(usize);

#[derive(Copy, Clone, Debug)]
enum PartyPhase {
    /// Starting phase, all messages matter.
    Prepare,
    /// Commit phase; prepare messages are now redundant.
    Commit,
    /// Resolution phase; commit and prepare messages are now redundant.
    Resolved,
    /// Party has acknowledged our resolution message.
    Acknowledged
}

#[derive(Clone, Debug)]
enum LocalPhase {
    Pre,
    Prepare { prepare: PbftRequest },
    Commit { commit: PbftRequest },
    Complete { req: PbftRequest },
    Fail
}

#[derive(Clone, Debug)]
struct PBFTPartyInfo {
    /// Number of times the message has been tried.
    nretries: usize,
    /// When to send the next message.
    when: Instant,
    /// Latest phase for a message that has been observed from this party.
    phase: PartyPhase,
    /// Whether we need to send an acknowledgement to this party.
    send_ack: Option<PbftAckState>
}

/// Outbound message structure for the Castro-Liskov PBFT consensus
/// protocol.
pub struct PBFTOutbound<RoundID> {
    round: PhantomData<RoundID>,
    /// Retry configuration.
    retry: Retry,
    /// My phase.
    phase: LocalPhase,
    /// State of all parties.
    parties: Vec<PBFTPartyInfo>,
    /// Parties that need a message sent.
    active: BitVec,
    /// Pending acknowledgements.
    acks: BitVec
}

impl From<usize> for OutboundPartyIdx {
    #[inline]
    fn from(val: usize) -> Self {
        OutboundPartyIdx(val)
    }
}

impl From<OutboundPartyIdx> for usize {
    #[inline]
    fn from(val: OutboundPartyIdx) -> usize {
        val.0
    }
}

impl<RoundID> PBFTOutbound<RoundID> {
    #[inline]
    fn new(
        nparties: usize,
        retry: Retry
    ) -> Self {
        let info = PBFTPartyInfo {
            when: Instant::now(),
            phase: PartyPhase::Prepare,
            nretries: 0,
            send_ack: None
        };

        debug!(target: "pbft-outbound",
               "creating outbound with {} parties",
               nparties);

        PBFTOutbound {
            round: PhantomData,
            parties: vec![info; nparties],
            phase: LocalPhase::Pre,
            retry: retry,
            active: bitvec![0; nparties],
            acks: bitvec![0; nparties]
        }
    }

    fn recv_prepare(
        &mut self,
        party_idx: usize
    ) {
        // If we're in prepare or earlier, we need to send an
        // acknowledgement; otherwise, our status update automatically
        // counts as one.
        if let LocalPhase::Pre | LocalPhase::Prepare { .. } = self.phase {
            match self.parties[party_idx].phase {
                PartyPhase::Prepare => {
                    trace!(target: "pbft-outbound",
                           "marking party (index {}) as needing prepare ack",
                           party_idx);

                    self.parties[party_idx].send_ack =
                        Some(PbftAckState::Prepare);
                    self.acks.set(party_idx, true);
                }
                _ => {
                    trace!(target: "pbft-outbound",
                           "party (index {}) is already past prepare phase",
                           party_idx);
                }
            }
        }
    }

    fn recv_commit(
        &mut self,
        party_idx: usize
    ) {
        debug!(target: "pbft-outbound",
               "logging commit message from party (index {})",
               party_idx);

        // Advance party to the commit phase if they aren't there already.
        if let PartyPhase::Prepare = self.parties[party_idx].phase {
            trace!(target: "pbft-outbound",
                   "recording party (index {}) as being in commit phase",
                   party_idx);

            self.parties[party_idx].phase = PartyPhase::Commit;
        }

        // If we're in a phase before commit, this cancels every
        // pending send.
        if let LocalPhase::Pre | LocalPhase::Prepare { .. } = self.phase {
            trace!(target: "pbft-outbound",
                   "marking party (index {}) as inactive",
                   party_idx);

            self.parties[party_idx].nretries = 0;
            self.active.set(party_idx, false);
        }

        // If we're in commit or earlier, we need to send an
        // acknowledgement; otherwise, our status update automatically
        // counts as one.
        if let LocalPhase::Pre |
        LocalPhase::Prepare { .. } |
        LocalPhase::Commit { .. } = self.phase
        {
            match self.parties[party_idx].phase {
                PartyPhase::Prepare | PartyPhase::Commit => {
                    trace!(target: "pbft-outbound",
                           "marking party (index {}) as needing commit ack",
                           party_idx);

                    self.parties[party_idx].send_ack =
                        Some(PbftAckState::Commit);
                    self.acks.set(party_idx, true);
                }
                _ => {
                    trace!(target: "pbft-outbound",
                           "party (index {}) is already past commit phase",
                           party_idx);
                }
            }
        }
    }

    fn recv_complete(
        &mut self,
        party_idx: usize
    ) {
        debug!(target: "pbft-outbound",
               "logging complete message from party (index {})",
               party_idx);

        // No matter what, we send an acknowledgement.
        self.parties[party_idx].send_ack = Some(PbftAckState::Complete);
        self.acks.set(party_idx, true);

        // Advance to the commit phase if we aren't there already.
        if let PartyPhase::Prepare | PartyPhase::Commit =
            self.parties[party_idx].phase
        {
            trace!(target: "pbft-outbound",
                   "recording party (index {}) as being in resolved phase",
                   party_idx);

            self.parties[party_idx].phase = PartyPhase::Resolved;
        }

        // If we're in a phase before resolved, this cancels every
        // pending send.
        if let LocalPhase::Pre |
        LocalPhase::Prepare { .. } |
        LocalPhase::Commit { .. } = self.phase
        {
            trace!(target: "pbft-outbound",
                   "marking party (index {}) as inactive",
                   party_idx);

            self.parties[party_idx].nretries = 0;
            self.active.set(party_idx, false);
        }
    }

    fn recv_fail(
        &mut self,
        party_idx: usize
    ) {
        debug!(target: "pbft-outbound",
               "logging fail message from party (index {})",
               party_idx);

        // No matter what, we send an acknowledgement.
        self.parties[party_idx].send_ack = Some(PbftAckState::Fail);
        self.acks.set(party_idx, true);

        // Advance to the commit phase if we aren't there already.
        if let PartyPhase::Prepare | PartyPhase::Commit =
            self.parties[party_idx].phase
        {
            trace!(target: "pbft-outbound",
                   "recording party (index {}) as being in resolved phase",
                   party_idx);

            self.parties[party_idx].phase = PartyPhase::Resolved;
        }

        // If we're in a phase before resolved, this cancels every
        // pending send.
        if let LocalPhase::Pre |
        LocalPhase::Prepare { .. } |
        LocalPhase::Commit { .. } = self.phase
        {
            trace!(target: "pbft-outbound",
                   "marking party (index {}) as inactive",
                   party_idx);

            self.parties[party_idx].nretries = 0;
            self.active.set(party_idx, false);
        }
    }

    fn recv_prepare_ack(
        &mut self,
        party_idx: usize
    ) {
        match &self.phase {
            // We're in the prepare phase; remove the party from the
            // active set.
            LocalPhase::Prepare { .. } => {
                trace!(target: "pbft-outbound",
                       "party (index {}) acknowledged our prepare message",
                       party_idx);

                self.parties[party_idx].nretries = 0;
                self.active.set(party_idx, false);
            }
            // Should not get a prepare acknowledgement before the
            // prepare phase.
            LocalPhase::Pre => {
                warn!(target: "pbft-outbound",
                      "premature prepare acknowledgement from party (index {})",
                      party_idx);
            }
            // We're already past the prepare phase; ignore.
            _ => {
                trace!(target: "pbft-outbound",
                       "ignoring prepare acknowledgement from party (index {})",
                       party_idx);
            }
        }
    }

    fn recv_commit_ack(
        &mut self,
        party_idx: usize
    ) {
        match &self.phase {
            // We're in the prepare phase; remove the party from the
            // active set.
            LocalPhase::Commit { .. } => {
                trace!(target: "pbft-outbound",
                       "party (index {}) acknowledged our commit message",
                       party_idx);

                self.parties[party_idx].nretries = 0;
                self.active.set(party_idx, false);
            }
            // Should not get a commit acknowledgement before the commit phase.
            LocalPhase::Pre | LocalPhase::Prepare { .. } => {
                warn!(target: "pbft-outbound",
                      "premature commit acknowledgement from party (index {})",
                      party_idx);
            }
            // We're already past the prepare phase; ignore.
            _ => {
                trace!(target: "pbft-outbound",
                       "ignoring commit acknowledgement from party (index {})",
                       party_idx);
            }
        }
    }

    fn recv_complete_ack(
        &mut self,
        party_idx: usize
    ) {
        match &self.phase {
            // We're in the prepare phase; remove the party from the
            // active set.
            LocalPhase::Complete { .. } => {
                trace!(target: "pbft-outbound",
                       "party (index {}) acknowledged our commit message",
                       party_idx);

                self.parties[party_idx].phase = PartyPhase::Acknowledged;
                self.parties[party_idx].nretries = 0;
                self.active.set(party_idx, false);
            }
            // Should not get a commit acknowledgement before the commit phase.
            LocalPhase::Pre |
            LocalPhase::Prepare { .. } |
            LocalPhase::Commit { .. } => {
                warn!(target: "pbft-outbound",
                      "premature complete acknowledgement from party (index {})",
                      party_idx);
            }
            // We're already past the prepare phase; ignore.
            LocalPhase::Fail => {
                warn!(target: "pbft-outbound",
                      "incorrect fail acknowledgement from party (index {})",
                      party_idx);
            }
        }
    }

    fn recv_fail_ack(
        &mut self,
        party_idx: usize
    ) {
        match &self.phase {
            // We're in the prepare phase; remove the party from the
            // active set.
            LocalPhase::Fail => {
                trace!(target: "pbft-outbound",
                       "party (index {}) acknowledged our fail message",
                       party_idx);

                self.parties[party_idx].phase = PartyPhase::Acknowledged;
                self.parties[party_idx].nretries = 0;
                self.active.set(party_idx, false);
            }
            // Should not get a commit acknowledgement before the commit phase.
            LocalPhase::Pre |
            LocalPhase::Prepare { .. } |
            LocalPhase::Commit { .. } => {
                warn!(target: "pbft-outbound",
                      "premature complete acknowledgement from party (index {})",
                      party_idx);
            }
            // We're already past the prepare phase; ignore.
            LocalPhase::Complete { .. } => {
                warn!(target: "pbft-outbound",
                      "incorrect fail acknowledgement from party (index {})",
                      party_idx);
            }
        }
    }
}

impl<RoundID> Outbound<RoundID, PbftMsg> for PBFTOutbound<RoundID>
where
    RoundID: Clone + Display + Ord + From<u128> + Into<u128>
{
    type CollectOutboundError = Infallible;
    type Config = PBFTOutboundConfig;
    type PartyID = OutboundPartyIdx;
    type RecvError = Infallible;

    #[inline]
    fn create(
        nparties: usize,
        config: PBFTOutboundConfig
    ) -> Self {
        let retry = config.take();

        PBFTOutbound::new(nparties, retry)
    }

    fn recv(
        &mut self,
        msg: &PbftContent,
        party: &OutboundPartyIdx
    ) -> Result<(), Self::RecvError> {
        let party_idx: usize = party.clone().into();
        let (ack, update) = match msg {
            PbftContent::UpdateAck(PbftUpdateAck { update, ack }) => {
                (Some(ack), Some(update))
            }
            PbftContent::Update(update) => (None, Some(update)),
            PbftContent::Ack(ack) => (Some(ack), None)
        };

        match update {
            Some(PbftStateUpdate::Prepare(_)) => self.recv_prepare(party_idx),
            Some(PbftStateUpdate::Commit(_)) => self.recv_commit(party_idx),
            Some(PbftStateUpdate::Complete(_)) => self.recv_complete(party_idx),
            Some(PbftStateUpdate::Fail(_)) => self.recv_fail(party_idx),
            None => {}
        }

        match ack {
            Some(PbftAckState::Prepare) => self.recv_prepare_ack(party_idx),
            Some(PbftAckState::Commit) => self.recv_commit_ack(party_idx),
            Some(PbftAckState::Complete) => self.recv_complete_ack(party_idx),
            Some(PbftAckState::Fail) => self.recv_fail_ack(party_idx),
            None => {}
        }

        Ok(())
    }

    fn collect_outbound<F>(
        &mut self,
        round: RoundID,
        mut func: F
    ) -> Result<Option<Instant>, Self::CollectOutboundError>
    where
        F: FnMut(OutboundGroup<PbftMsg>) {
        let nparties = self.parties.len();
        let mut msgs: HashMap<PbftMsg, BitVec> =
            HashMap::with_capacity(nparties);
        let now = Instant::now();
        let mut earliest = None;
        let round: u128 = round.into();

        debug!(target: "pbft-outbound",
               "collecting pending outbound messages");

        let sends = self.active.clone() | &self.acks;

        // Clear out acknowledgements; we will only send one, and we
        // will always send them here.
        self.acks.fill(false);

        for i in sends.iter_ones() {
            let req = if self.active[i] {
                let party = &mut self.parties[i];

                if party.when <= now {
                    trace!(target: "pbft-outbound",
                           "party (index {}) is ready to send",
                           i);

                    let delay = self.retry.retry_delay(party.nretries);

                    trace!(target: "pbft-outbound",
                           "party (index {}) next send in {}.{:03}s",
                           i, delay.as_secs(), delay.subsec_millis());

                    party.nretries += 1;
                    party.when = now + delay;
                }

                match earliest {
                    Some(when) if when > party.when => {
                        earliest = Some(party.when)
                    }
                    None => earliest = Some(party.when),
                    _ => {}
                }

                // Generate the outgoing request
                match &self.phase {
                    LocalPhase::Pre => None,
                    LocalPhase::Prepare { prepare } => {
                        Some(PbftStateUpdate::Prepare(prepare.clone()))
                    }
                    LocalPhase::Commit { commit } => {
                        Some(PbftStateUpdate::Commit(commit.clone()))
                    }
                    LocalPhase::Complete { req } => {
                        Some(PbftStateUpdate::Complete(req.clone()))
                    }
                    LocalPhase::Fail => Some(PbftStateUpdate::Fail(Null))
                }
            } else {
                trace!(target: "pbft-outbound",
                       "{} not active",
                       i);

                None
            };

            let ack = self.parties[i].send_ack;

            self.parties[i].send_ack = None;

            match (req, ack) {
                (Some(req), Some(ack)) => {
                    let update_ack = PbftUpdateAck {
                        ack: ack,
                        update: req
                    };
                    let content = PbftContent::UpdateAck(update_ack);

                    debug!(target: "pbft-outbound",
                           "sending state update and ack to party (index {})",
                           i);

                    match msgs.entry(PbftMsg::create(round, content)) {
                        Entry::Occupied(mut ent) => ent.get_mut().set(i, true),
                        Entry::Vacant(ent) => {
                            let mut bitvec = bitvec![0; nparties];

                            bitvec.set(i, true);

                            ent.insert(bitvec);
                        }
                    }
                }
                (Some(req), None) => {
                    let content = PbftContent::Update(req);

                    debug!(target: "pbft-outbound",
                           "sending state update to party (index {})",
                           i);

                    match msgs.entry(PbftMsg::create(round, content)) {
                        Entry::Occupied(mut ent) => ent.get_mut().set(i, true),
                        Entry::Vacant(ent) => {
                            let mut bitvec = bitvec![0; nparties];

                            bitvec.set(i, true);

                            ent.insert(bitvec);
                        }
                    }
                }
                (None, Some(ack)) => {
                    let content = PbftContent::Ack(ack);

                    debug!(target: "pbft-outbound",
                           "sending bare ack to party (index {})",
                           i);

                    match msgs.entry(PbftMsg::create(round, content)) {
                        Entry::Occupied(mut ent) => ent.get_mut().set(i, true),
                        Entry::Vacant(ent) => {
                            let mut bitvec = bitvec![0; nparties];

                            bitvec.set(i, true);

                            ent.insert(bitvec);
                        }
                    }
                }
                _ => {
                    error!(target: "pbft-outbound",
                           "should not see no-content message case");
                }
            }
        }

        for (msg, parties) in msgs.into_iter() {
            func(OutboundGroup::create(parties, msg))
        }

        Ok(earliest)
    }

    fn finished(&self) -> bool {
        for party in self.parties.iter() {
            match (party.phase, party.send_ack) {
                (PartyPhase::Acknowledged, None) => {}
                _ => return false
            }
        }

        true
    }
}

impl<RoundID> PBFTOutboundSend<PbftRequest> for PBFTOutbound<RoundID> {
    fn send_prepare(
        &mut self,
        req: &PbftRequest
    ) {
        debug!(target: "pbft-outbound",
               "requested to send prepare messages");

        // Smoke check: ensure that we're in the right phase.
        match &self.phase {
            LocalPhase::Pre => {
                let now = Instant::now();

                self.phase = LocalPhase::Prepare {
                    prepare: req.clone()
                };

                trace!(target: "pbft-outbound",
                       "set local phase to {}",
                       self.phase);

                for i in 0..self.parties.len() {
                    match &self.parties[i].phase {
                        PartyPhase::Prepare => {
                            trace!(target: "pbft-outbound",
                                   "setting party (index {}) to active",
                                   i);

                            // Reset the parties retries and schedule it
                            // for immediate sending.
                            let party = &mut self.parties[i];

                            party.nretries = 0;
                            party.when = now;
                            self.active.set(i, true);
                        }
                        // Party is in a later phase already, so
                        // nothing happens.
                        phase => {
                            trace!(target: "pbft-outbound",
                                   "party (index {}) is already in phase {}",
                                   i, phase);
                        }
                    }
                }
            }
            // Shouldn't be calling this from a different phase.
            phase => {
                error!(target: "pbft-outbound",
                       "calling send_prepare from wrong phase ({})",
                       phase);
            }
        }
    }

    fn send_commit(
        &mut self,
        req: &PbftRequest
    ) {
        debug!(target: "pbft-outbound",
               "requested to send commit messages");

        // Smoke check: ensure that we're in the right phase.
        match &self.phase {
            LocalPhase::Pre | LocalPhase::Prepare { .. } => {
                let now = Instant::now();

                self.phase = LocalPhase::Commit {
                    commit: req.clone()
                };

                trace!(target: "pbft-outbound",
                       "set local phase to {}",
                       self.phase);

                for i in 0..self.parties.len() {
                    match &self.parties[i].phase {
                        PartyPhase::Prepare | PartyPhase::Commit => {
                            trace!(target: "pbft-outbound",
                                   "setting party (index {}) to active",
                                   i);

                            // Reset the parties retries and schedule it
                            // for immediate sending.
                            let party = &mut self.parties[i];

                            party.nretries = 0;
                            party.when = now;
                            self.active.set(i, true);

                            if party.send_ack == Some(PbftAckState::Prepare) {
                                party.send_ack = None;
                                self.acks.set(i, false);
                            }
                        }
                        // Party is in a later phase already, so
                        // nothing happens.
                        phase => {
                            trace!(target: "pbft-outbound",
                                   "party (index {}) is already in phase {}",
                                   i, phase);
                        }
                    }
                }
            }
            // Shouldn't be calling this from a different phase.
            phase => {
                error!(target: "pbft-outbound",
                       "calling send_commit from wrong phase ({})",
                       phase);
            }
        }
    }

    fn send_complete(
        &mut self,
        req: &PbftRequest
    ) {
        debug!(target: "pbft-outbound",
               "requested to send complete messages");

        // Smoke check: ensure that we're in the right phase.
        match &self.phase {
            LocalPhase::Pre |
            LocalPhase::Prepare { .. } |
            LocalPhase::Commit { .. } => {
                let now = Instant::now();

                self.phase = LocalPhase::Complete { req: req.clone() };

                trace!(target: "pbft-outbound",
                       "set local phase to {}",
                       self.phase);

                for i in 0..self.parties.len() {
                    match &mut self.parties[i].phase {
                        PartyPhase::Prepare |
                        PartyPhase::Commit |
                        PartyPhase::Resolved => {
                            trace!(target: "pbft-outbound",
                                   "setting party (index {}) to active",
                                   i);

                            // Reset the parties retries and schedule it
                            // for immediate sending.
                            let party = &mut self.parties[i];

                            party.nretries = 0;
                            party.when = now;
                            self.active.set(i, true);

                            match party.send_ack {
                                Some(PbftAckState::Prepare) |
                                Some(PbftAckState::Commit) => {
                                    party.send_ack = None;
                                    self.acks.set(i, false);
                                }
                                _ => {}
                            }
                        }
                        // Party is in a later phase already, so
                        // nothing happens.
                        phase => {
                            trace!(target: "pbft-outbound",
                                   "party (index {}) is already in phase {}",
                                   i, phase);
                        }
                    }
                }
            }
            // Shouldn't be calling this from a different phase.
            phase => {
                error!(target: "pbft-outbound",
                       "calling send_complete from wrong phase ({})",
                       phase);
            }
        }
    }

    fn send_fail(&mut self) {
        debug!(target: "pbft-outbound",
               "requested to send fail messages");

        // Smoke check: ensure that we're in the right phase.
        match &self.phase {
            LocalPhase::Pre |
            LocalPhase::Prepare { .. } |
            LocalPhase::Commit { .. } => {
                let now = Instant::now();

                self.phase = LocalPhase::Fail;

                trace!(target: "pbft-outbound",
                       "set local phase to {}",
                       self.phase);

                for i in 0..self.parties.len() {
                    match &mut self.parties[i].phase {
                        PartyPhase::Prepare |
                        PartyPhase::Commit |
                        PartyPhase::Resolved => {
                            trace!(target: "pbft-outbound",
                                   "setting party (index {}) to active",
                                   i);

                            // Reset the parties retries and schedule it
                            // for immediate sending.
                            let party = &mut self.parties[i];

                            party.nretries = 0;
                            party.when = now;
                            self.active.set(i, true);

                            match party.send_ack {
                                Some(PbftAckState::Prepare) |
                                Some(PbftAckState::Commit) => {
                                    party.send_ack = None;
                                    self.acks.set(i, false);
                                }
                                _ => {}
                            }
                        }
                        // Party is in a later phase already, so
                        // nothing happens.
                        phase => {
                            trace!(target: "pbft-outbound",
                                   "party (index {}) is already in phase {}",
                                   i, phase);
                        }
                    }
                }
            }
            // Shouldn't be calling this from a different phase.
            phase => {
                error!(target: "pbft-outbound",
                       "calling send_fail from wrong phase ({})",
                       phase);
            }
        }
    }
}

impl Display for PartyPhase {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            PartyPhase::Prepare => write!(f, "prepare"),
            PartyPhase::Commit => write!(f, "commit"),
            PartyPhase::Resolved => write!(f, "resolved"),
            PartyPhase::Acknowledged => write!(f, "acknowledged")
        }
    }
}

impl Display for LocalPhase {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            LocalPhase::Pre => write!(f, "pre-prepare"),
            LocalPhase::Prepare { .. } => write!(f, "prepare"),
            LocalPhase::Commit { .. } => write!(f, "commit"),
            LocalPhase::Complete { .. } => write!(f, "complete"),
            LocalPhase::Fail => write!(f, "failed")
        }
    }
}

impl Display for OutboundPartyIdx {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        self.0.fmt(f)
    }
}

#[cfg(test)]
use std::collections::HashSet;

#[cfg(test)]
use bitvec::order::Lsb0;

#[cfg(test)]
use crate::generated::req::PbftView;

#[test]
fn test_empty_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![].drain(..).collect();
    let mut actual = HashSet::new();

    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let ack = PbftContent::Ack(PbftAckState::Prepare);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone())]
            .drain(..)
            .collect();

    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_collect_outbound_twice() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let ack = PbftContent::Ack(PbftAckState::Prepare);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone())]
            .drain(..)
            .collect();

    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual);

    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![].drain(..).collect();
    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_prepare(&req);
    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Commit);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_prepare(&req);
    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Commit);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Complete);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_prepare(&req);
    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Complete);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Fail);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_prepare(&req);
    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Fail);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_prepare_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_prepare(&req);
    outbound.recv_prepare_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_ack_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_prepare_ack(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_commit_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_prepare(&req);
    outbound.recv_commit_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_ack_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_commit_ack(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_complete_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_prepare(&req);
    outbound.recv_complete_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_ack_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_complete_ack(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_fail_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_prepare(&req);
    outbound.recv_fail_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_ack_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_fail_ack(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_prepare_recv_prepare_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Prepare);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_prepare(&req);
    outbound.recv_prepare(0);
    outbound.recv_prepare_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_prepare_ack_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Prepare);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_prepare(&req);
    outbound.recv_prepare_ack(0);
    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_ack_send_prepare_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare_ack(0);
    outbound.send_prepare(&req);
    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_send_prepare_recv_prepare_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Prepare);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare(0);
    outbound.send_prepare(&req);
    outbound.recv_prepare_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_ack_recv_prepare_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare_ack(0);
    outbound.recv_prepare(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_recv_prepare_ack_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare(0);
    outbound.recv_prepare_ack(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_prepare_recv_commit_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_prepare(&req);
    outbound.recv_prepare(0);
    outbound.recv_commit_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_commit_ack_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_prepare(&req);
    outbound.recv_commit_ack(0);
    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_ack_send_prepare_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit_ack(0);
    outbound.send_prepare(&req);
    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_send_prepare_recv_commit_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare(0);
    outbound.send_prepare(&req);
    outbound.recv_commit_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_ack_recv_prepare_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit_ack(0);
    outbound.recv_prepare(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_recv_commit_ack_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare(0);
    outbound.recv_commit_ack(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_prepare_recv_complete_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_prepare(&req);
    outbound.recv_prepare(0);
    outbound.recv_complete_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_complete_ack_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_prepare(&req);
    outbound.recv_complete_ack(0);
    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_ack_send_prepare_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete_ack(0);
    outbound.send_prepare(&req);
    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_send_prepare_recv_complete_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare(0);
    outbound.send_prepare(&req);
    outbound.recv_complete_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_ack_recv_prepare_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete_ack(0);
    outbound.recv_prepare(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_recv_complete_ack_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare(0);
    outbound.recv_complete_ack(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_prepare_recv_fail_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_prepare(&req);
    outbound.recv_prepare(0);
    outbound.recv_fail_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_prepare_recv_fail_ack_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_prepare(&req);
    outbound.recv_fail_ack(0);
    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_ack_send_prepare_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail_ack(0);
    outbound.send_prepare(&req);
    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_send_prepare_recv_fail_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare(0);
    outbound.send_prepare(&req);
    outbound.recv_fail_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_ack_recv_prepare_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail_ack(0);
    outbound.recv_prepare(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_recv_fail_ack_send_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Prepare(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Prepare,
        update: PbftStateUpdate::Prepare(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare(0);
    outbound.recv_fail_ack(0);
    outbound.send_prepare(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let ack = PbftContent::Ack(PbftAckState::Commit);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone())]
            .drain(..)
            .collect();

    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_collect_outbound_twice() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let ack = PbftContent::Ack(PbftAckState::Commit);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone())]
            .drain(..)
            .collect();

    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual);

    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![].drain(..).collect();
    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_commit(&req);
    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_prepare(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_commit(&req);
    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Complete);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_commit(&req);
    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Complete);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Fail);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_commit(&req);
    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Fail);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_prepare_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_commit(&req);
    outbound.recv_prepare_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_ack_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_prepare_ack(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_commit_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_commit(&req);
    outbound.recv_commit_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_ack_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_commit_ack(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_complete_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_commit(&req);
    outbound.recv_complete_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_ack_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_complete_ack(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_fail_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_commit(&req);
    outbound.recv_fail_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_ack_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_fail_ack(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_commit_recv_prepare_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_commit(&req);
    outbound.recv_commit(0);
    outbound.recv_prepare_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_prepare_ack_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_commit(&req);
    outbound.recv_prepare_ack(0);
    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_ack_send_commit_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare_ack(0);
    outbound.send_commit(&req);
    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_send_commit_recv_prepare_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit(0);
    outbound.send_commit(&req);
    outbound.recv_prepare_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_ack_recv_commit_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare_ack(0);
    outbound.recv_commit(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_recv_prepare_ack_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit(0);
    outbound.recv_prepare_ack(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_commit_recv_commit_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Commit);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_commit(&req);
    outbound.recv_commit(0);
    outbound.recv_commit_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_commit_ack_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Commit);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_commit(&req);
    outbound.recv_commit_ack(0);
    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_ack_send_commit_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit_ack(0);
    outbound.send_commit(&req);
    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_send_commit_recv_commit_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Commit);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit(0);
    outbound.send_commit(&req);
    outbound.recv_commit_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_ack_recv_commit_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit_ack(0);
    outbound.recv_commit(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_recv_commit_ack_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit(0);
    outbound.recv_commit_ack(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_commit_recv_complete_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_commit(&req);
    outbound.recv_commit(0);
    outbound.recv_complete_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_complete_ack_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_commit(&req);
    outbound.recv_complete_ack(0);
    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_ack_send_commit_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete_ack(0);
    outbound.send_commit(&req);
    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_send_commit_recv_complete_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit(0);
    outbound.send_commit(&req);
    outbound.recv_complete_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_ack_recv_commit_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete_ack(0);
    outbound.recv_commit(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_recv_complete_ack_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit(0);
    outbound.recv_complete_ack(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_commit_recv_fail_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_commit(&req);
    outbound.recv_commit(0);
    outbound.recv_fail_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_commit_recv_fail_ack_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_commit(&req);
    outbound.recv_fail_ack(0);
    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_ack_send_commit_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail_ack(0);
    outbound.send_commit(&req);
    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_send_commit_recv_fail_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit(0);
    outbound.send_commit(&req);
    outbound.recv_fail_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_ack_recv_commit_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail_ack(0);
    outbound.recv_commit(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_recv_fail_ack_send_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Commit(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Commit,
        update: PbftStateUpdate::Commit(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit(0);
    outbound.recv_fail_ack(0);
    outbound.send_commit(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let ack = PbftContent::Ack(PbftAckState::Complete);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone())]
            .drain(..)
            .collect();

    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_collect_outbound_twice() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let ack = PbftContent::Ack(PbftAckState::Complete);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone())]
            .drain(..)
            .collect();

    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual);

    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![].drain(..).collect();
    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_complete(&req);
    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_prepare(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_complete(&req);
    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_commit(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_complete(&req);
    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_complete(&req);
    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_prepare_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_complete(&req);
    outbound.recv_prepare_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_ack_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_prepare_ack(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_commit_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_complete(&req);
    outbound.recv_commit_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_ack_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_commit_ack(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_complete_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_complete(&req);
    outbound.recv_complete_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_ack_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_complete_ack(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_fail_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_complete(&req);
    outbound.recv_fail_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_ack_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_fail_ack(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_complete_recv_prepare_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_complete(&req);
    outbound.recv_complete(0);
    outbound.recv_prepare_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_prepare_ack_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_complete(&req);
    outbound.recv_prepare_ack(0);
    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_ack_send_complete_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare_ack(0);
    outbound.send_complete(&req);
    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_send_complete_recv_prepare_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.send_complete(&req);
    outbound.recv_prepare_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_ack_recv_complete_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare_ack(0);
    outbound.recv_complete(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_recv_prepare_ack_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.recv_prepare_ack(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_complete_recv_commit_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_complete(&req);
    outbound.recv_complete(0);
    outbound.recv_commit_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_commit_ack_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_complete(&req);
    outbound.recv_commit_ack(0);
    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_ack_send_complete_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit_ack(0);
    outbound.send_complete(&req);
    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_send_complete_recv_commit_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.send_complete(&req);
    outbound.recv_commit_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_ack_recv_complete_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit_ack(0);
    outbound.recv_complete(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_recv_commit_ack_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.recv_commit_ack(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_complete_recv_complete_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Complete);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_complete(&req);
    outbound.recv_complete(0);
    outbound.recv_complete_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_complete_ack_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Complete);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_complete(&req);
    outbound.recv_complete_ack(0);
    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_ack_send_complete_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete_ack(0);
    outbound.send_complete(&req);
    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_send_complete_recv_complete_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::Ack(PbftAckState::Complete);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.send_complete(&req);
    outbound.recv_complete_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_ack_recv_complete_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete_ack(0);
    outbound.recv_complete(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_recv_complete_ack_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.recv_complete_ack(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_complete_recv_fail_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_complete(&req);
    outbound.recv_complete(0);
    outbound.recv_fail_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_complete_recv_fail_ack_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_complete(&req);
    outbound.recv_fail_ack(0);
    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_ack_send_complete_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail_ack(0);
    outbound.send_complete(&req);
    outbound.recv_complete(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_send_complete_recv_fail_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.send_complete(&req);
    outbound.recv_fail_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_ack_recv_complete_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail_ack(0);
    outbound.recv_complete(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_recv_fail_ack_send_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let msg = PbftContent::Update(PbftStateUpdate::Complete(req.clone()));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Complete(req.clone())
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.recv_fail_ack(0);
    outbound.send_complete(&req);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let ack = PbftContent::Ack(PbftAckState::Fail);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone())]
            .drain(..)
            .collect();

    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_collect_outbound_twice() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let ack = PbftContent::Ack(PbftAckState::Fail);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone())]
            .drain(..)
            .collect();

    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual);

    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![].drain(..).collect();
    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_prepare_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_fail();
    outbound.recv_prepare(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_prepare(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_commit_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_fail();
    outbound.recv_commit(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_commit(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_complete_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Complete,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_fail();
    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_prepare_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_fail();
    outbound.recv_prepare_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_ack_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_prepare_ack(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_commit_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_fail();
    outbound.recv_commit_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_ack_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_commit_ack(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_complete_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_fail();
    outbound.recv_complete_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_ack_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_complete_ack(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_fail_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.send_fail();
    outbound.recv_fail_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_ack_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let expected: HashSet<OutboundGroup<PbftMsg>> =
        vec![OutboundGroup::create(bitvec![1, 1, 1, 1], msg.clone())]
            .drain(..)
            .collect();

    outbound.recv_fail_ack(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_fail_recv_prepare_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_fail();
    outbound.recv_fail(0);
    outbound.recv_prepare_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_prepare_ack_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_fail();
    outbound.recv_prepare_ack(0);
    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_ack_send_fail_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare_ack(0);
    outbound.send_fail();
    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_send_fail_recv_prepare_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail(0);
    outbound.send_fail();
    outbound.recv_prepare_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_prepare_ack_recv_fail_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_prepare_ack(0);
    outbound.recv_fail(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_recv_prepare_ack_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail(0);
    outbound.recv_prepare_ack(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_fail_recv_commit_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_fail();
    outbound.recv_fail(0);
    outbound.recv_commit_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_commit_ack_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_fail();
    outbound.recv_commit_ack(0);
    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_ack_send_fail_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit_ack(0);
    outbound.send_fail();
    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_send_fail_recv_commit_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail(0);
    outbound.send_fail();
    outbound.recv_commit_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_commit_ack_recv_fail_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_commit_ack(0);
    outbound.recv_fail(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_recv_commit_ack_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail(0);
    outbound.recv_commit_ack(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_fail_recv_complete_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_fail();
    outbound.recv_fail(0);
    outbound.recv_complete_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_complete_ack_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_fail();
    outbound.recv_complete_ack(0);
    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_ack_send_fail_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete_ack(0);
    outbound.send_fail();
    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_send_fail_recv_complete_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail(0);
    outbound.send_fail();
    outbound.recv_complete_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_complete_ack_recv_fail_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_complete_ack(0);
    outbound.recv_fail(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_recv_complete_ack_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail(0);
    outbound.recv_complete_ack(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_fail_recv_fail_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::Ack(PbftAckState::Fail);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_fail();
    outbound.recv_fail(0);
    outbound.recv_fail_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_send_fail_recv_fail_ack_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::Ack(PbftAckState::Fail);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.send_fail();
    outbound.recv_fail_ack(0);
    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_ack_send_fail_recv_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail_ack(0);
    outbound.send_fail();
    outbound.recv_fail(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_send_fail_recv_fail_ack_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::Ack(PbftAckState::Fail);
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail(0);
    outbound.send_fail();
    outbound.recv_fail_ack(0);

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_ack_recv_fail_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail_ack(0);
    outbound.recv_fail(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_recv_fail_recv_fail_ack_send_fail_collect_outbound() {
    let round_id = 7;
    let mut outbound: PBFTOutbound<u128> =
        PBFTOutbound::new(4, Retry::default());
    let msg = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let msg = PbftMsg::create(round_id, msg);
    let ack = PbftContent::UpdateAck(PbftUpdateAck {
        ack: PbftAckState::Fail,
        update: PbftStateUpdate::Fail(Null)
    });
    let ack = PbftMsg::create(round_id, ack);
    let expected: HashSet<OutboundGroup<PbftMsg>> = vec![
        OutboundGroup::create(bitvec![1, 0, 0, 0], ack.clone()),
        OutboundGroup::create(bitvec![0, 1, 1, 1], msg.clone()),
    ]
    .drain(..)
    .collect();

    outbound.recv_fail(0);
    outbound.recv_fail_ack(0);
    outbound.send_fail();

    let mut actual = HashSet::new();
    outbound
        .collect_outbound(round_id, |msg| {
            actual.insert(msg);
        })
        .unwrap();

    assert_eq!(expected, actual)
}
