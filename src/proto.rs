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

//! Top-level Castro-Liskov PBFT consensus protocol implementation.
use std::convert::Infallible;
use std::fmt::Display;
use std::hash::Hash;
use std::marker::PhantomData;

use constellation_common::config::Create;
use constellation_common::hashid::HashAlgo;
use constellation_consensus_common::config::SingleRoundConfig;
use constellation_consensus_common::parties::StaticParties;
use constellation_consensus_common::parties::PartyTypes;
use constellation_consensus_common::parties::RoundIDGenTypes;
use constellation_consensus_common::parties::RoundPartyIDTypes;
use constellation_consensus_common::parties::RoundPartyIdxTypes;
use constellation_consensus_common::proto::ConsensusProto;
use constellation_consensus_common::round::SingleRound;
use constellation_consensus_common::round::SingleRoundCreateError;

use crate::config::PBFTConfig;
use crate::config::PBFTProtoStateConfig;
use crate::outbound::OutboundPartyIdx;
use crate::state::PBFTProtoState;
use crate::state::PBFTProtoTypes;
use crate::state::PBFTRoundStateCreateError;

/// Castro-Liskov PBFT consensus protocol implementation.
pub struct PBFTProto<H, Types>
where
    Types: RoundIDGenTypes + RoundPartyIDTypes + PartyTypes,
    H: HashAlgo,
    H::HashID: Clone + Display + Eq + Hash {
    hash: PhantomData<H>,
    types: PhantomData<Types>,
    outbound_config: SingleRoundConfig<PBFTProtoStateConfig>,
}

impl<H, Types> Create for PBFTProto<H, Types>
where
    Types: RoundIDGenTypes + RoundPartyIDTypes + PartyTypes,
    H: HashAlgo,
    H::HashID: Clone + Display + Eq + Hash {
    type Config = PBFTConfig;
    type CreateError = Infallible;

    fn create(config: Self::Config) -> Result<Self, Self::CreateError> {
        let outbound_config = config.take();

        Ok(PBFTProto {
            types: PhantomData,
            hash: PhantomData,
            outbound_config: outbound_config,
        })
    }
}

impl<H, Types> ConsensusProto<StaticParties<Types::PartyID>, Types>
    for PBFTProto<H, Types>
where
    Types: RoundIDGenTypes + PartyTypes
        + RoundPartyIdxTypes<PartyRoundIdx = OutboundPartyIdx>,
    Types::RoundID: From<u128> + Into<u128>,
    H: Default + HashAlgo,
    H::HashID: Clone + Display + Eq + Hash {
    type ProtoTypes = PBFTProtoTypes;
    type Rounds = SingleRound<
        PBFTProtoState<H, Types::PartyID>,
        Types,
        PBFTProtoTypes
    >;
    type RoundsError<PartiesErr>
        = SingleRoundCreateError<Infallible, PBFTRoundStateCreateError<Types::PartyID>>
    where
        PartiesErr: Display;
    type State = PBFTProtoState<H, Types::PartyID>;

    fn rounds(
        &self,
        round_ids: Types::RoundIDs
    ) -> Result<Self::Rounds, Self::RoundsError<Infallible>> {
        SingleRound::create(round_ids, self.outbound_config.clone())
    }
}
