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

//! Configuration objects.
use constellation_common::hashid::CompoundHashAlgo;
use constellation_common::retry::Retry;
use constellation_consensus_common::config::SingleRoundConfig;
use serde::Deserialize;
use serde::Serialize;

/// Configuration for a PBFT protocol instance.
#[derive(
    Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "pbft-config")]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct PBFTConfig {
    // Maximum number of concurrent rounds that
    // can execute at once.
    // max_concurrent_rounds: usize,
    // Number of rounds before we start
    // proposing view changes.
    // view_change_rounds: usize,
    // Wall-clock time before we start proposing
    // view changes.
    // view_change_time: Option<Duration>
    #[serde(flatten)]
    state: SingleRoundConfig<PBFTProtoStateConfig>
}

/// Configuration for individual rounds for the PBFT consensus protocol.
#[derive(
    Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "pbft-state-config")]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct PBFTProtoStateConfig {
    /// Name of the hash function used on parties.
    #[serde(default)]
    party_hash: CompoundHashAlgo,
    /// Outbound buffer configurations.
    #[serde(default)]
    #[serde(flatten)]
    outbound: PBFTOutboundConfig
}

/// Configuration for the PBFT outbound message buffer.
#[derive(
    Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "pbft-config")]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct PBFTOutboundConfig {
    #[serde(default)]
    retry: Retry
}

impl PBFTProtoStateConfig {
    #[inline]
    pub fn create(
        party_hash: CompoundHashAlgo,
        outbound: PBFTOutboundConfig
    ) -> Self {
        PBFTProtoStateConfig {
            party_hash: party_hash,
            outbound: outbound
        }
    }

    #[inline]
    pub fn party_hash(&self) -> &CompoundHashAlgo {
        &self.party_hash
    }

    #[inline]
    pub fn outbound(&self) -> &PBFTOutboundConfig {
        &self.outbound
    }

    #[inline]
    pub fn take(self) -> (CompoundHashAlgo, PBFTOutboundConfig) {
        (self.party_hash, self.outbound)
    }
}

impl PBFTConfig {
    #[inline]
    pub fn create(state: SingleRoundConfig<PBFTProtoStateConfig>) -> Self {
        PBFTConfig { state: state }
    }

    #[inline]
    pub fn state(&self) -> &SingleRoundConfig<PBFTProtoStateConfig> {
        &self.state
    }

    #[inline]
    pub fn take(self) -> SingleRoundConfig<PBFTProtoStateConfig> {
        self.state
    }
}

impl PBFTOutboundConfig {
    #[inline]
    pub fn create(retry: Retry) -> Self {
        PBFTOutboundConfig { retry: retry }
    }

    #[inline]
    pub fn retry(&self) -> &Retry {
        &self.retry
    }

    #[inline]
    pub fn take(self) -> Retry {
        self.retry
    }
}
