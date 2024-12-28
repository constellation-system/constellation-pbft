// Copyright © 2024 The Johns Hopkins Applied Physics Laboratory LLC.
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

//! Top-level Castro-Liskov PBFT consensus protocol implementation.
use std::convert::Infallible;
use std::fmt::Display;
use std::hash::Hash;
use std::marker::PhantomData;

use constellation_common::codec::DatagramCodec;
use constellation_consensus_common::config::SingleRoundConfig;
use constellation_consensus_common::parties::StaticParties;
use constellation_consensus_common::proto::ConsensusProto;
use constellation_consensus_common::proto::ConsensusProtoRounds;
use constellation_consensus_common::round::SingleRound;
use constellation_consensus_common::round::SingleRoundCreateError;
use serde::Deserialize;
use serde::Serialize;

use crate::config::PBFTConfig;
use crate::config::PBFTProtoStateConfig;
use crate::msgs::PbftMsg;
use crate::outbound::OutboundPartyIdx;
use crate::outbound::PBFTOutbound;
use crate::state::PBFTProtoState;
use crate::state::PBFTRoundStateCreateError;

/// Castro-Liskov PBFT consensus protocol implementation.
pub struct PBFTProto<RoundIDs, Party>
where
    RoundIDs: Iterator,
    RoundIDs::Item: Clone + Display + From<u128> + Into<u128> + Ord,
    Party: Clone + Eq + Hash {
    party: PhantomData<Party>,
    round_ids: PhantomData<RoundIDs>,
    outbound_config: SingleRoundConfig<PBFTProtoStateConfig>
}

impl<RoundIDs, Party, Codec> ConsensusProto<Party, Codec>
    for PBFTProto<RoundIDs, Party>
where
    RoundIDs: Iterator,
    RoundIDs::Item: Clone + Display + From<u128> + Into<u128> + Ord,
    Party: Clone + Display + Eq + Hash,
    Codec: Clone + DatagramCodec<Party>
{
    type Config = PBFTConfig;
    type CreateError = Infallible;

    fn create(
        config: Self::Config,
        _codec: Codec
    ) -> Result<Self, Self::CreateError> {
        let outbound_config = config.take();

        Ok(PBFTProto {
            party: PhantomData,
            round_ids: PhantomData,
            outbound_config: outbound_config
        })
    }
}

impl<RoundIDs, PartyID, Party, Codec>
    ConsensusProtoRounds<
        RoundIDs,
        PartyID,
        Party,
        Codec,
        StaticParties<PartyID>
    > for PBFTProto<RoundIDs, Party>
where
    RoundIDs: Iterator,
    RoundIDs::Item: Clone + Display + From<u128> + Into<u128> + Ord + Send,
    PartyID: Clone + Display + Eq + Hash + From<usize> + Into<usize> + Ord,
    Party: Clone + for<'a> Deserialize<'a> + Display + Eq + Hash + Serialize,
    Codec: Clone + DatagramCodec<Party>
{
    type Msg = PbftMsg;
    type Out = PBFTOutbound<RoundIDs::Item>;
    type RoundPartyIdx = OutboundPartyIdx;
    type Rounds = SingleRound<
        PBFTProtoState<PartyID>,
        RoundIDs,
        PartyID,
        PbftMsg,
        PBFTOutbound<RoundIDs::Item>
    >;
    type RoundsError<PartiesErr> = SingleRoundCreateError<
        Infallible,
        PBFTRoundStateCreateError<PartyID>
    >
    where PartiesErr: Display;
    type State = PBFTProtoState<PartyID>;

    fn rounds(
        &self,
        round_ids: RoundIDs,
    ) -> Result<Self::Rounds, Self::RoundsError<Infallible>> {
        SingleRound::create(
            round_ids,
            self.outbound_config.clone()
        )
    }
}
