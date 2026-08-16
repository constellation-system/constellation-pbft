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

//! Configuration objects.
use std::time::Duration;

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
    #[serde(flatten)]
    state: SingleRoundConfig<PBFTProtoStateConfig>
}

/// Configuration for individual rounds for the PBFT consensus protocol.
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "pbft-state-config")]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct PBFTProtoStateConfig {
    /// Number of rounds before we start proposing view changes.
    #[serde(default = "PBFTProtoStateConfig::default_view_change_rounds")]
    view_change_rounds: usize,
    /// Number of failed rounds before we start proposing view
    /// changes.
    #[serde(default = "PBFTProtoStateConfig::default_view_change_failures")]
    view_change_failures: usize,
    /// Number of consecutive failed rounds before we start proposing
    /// view changes.
    #[serde(
        default = "PBFTProtoStateConfig::default_view_change_consecutive_failures"
    )]
    view_change_consecutive_failures: usize,
    /// Wall-clock time before we start proposing view changes.
    #[serde(default = "PBFTProtoStateConfig::default_view_change_time")]
    view_change_time: Option<Duration>,
    /// Wall-clock time without a successful round before we start
    /// proposing view changes.
    ///
    /// This will not trigger if there are no pending transactions.
    #[serde(default = "PBFTProtoStateConfig::default_view_change_stall_time")]
    view_change_stall_time: Option<Duration>,
    /// Outbound buffer configurations.
    #[serde(default)]
    #[serde(flatten)]
    outbound: PBFTOutboundConfig
}

impl Default for PBFTProtoStateConfig {
    #[inline]
    fn default() -> Self {
        PBFTProtoStateConfig {
            view_change_rounds:
                PBFTProtoStateConfig::default_view_change_rounds(),
            view_change_failures:
                PBFTProtoStateConfig::default_view_change_failures(),
            view_change_consecutive_failures:
                PBFTProtoStateConfig::default_view_change_consecutive_failures(),
            view_change_time: PBFTProtoStateConfig::default_view_change_time(),
            view_change_stall_time:
                PBFTProtoStateConfig::default_view_change_stall_time(),
            outbound: PBFTOutboundConfig::default()
        }
    }
}

/// Configuration for the PBFT outbound message buffer.
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "pbft-config")]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct PBFTOutboundConfig {
    #[serde(default = "PBFTOutboundConfig::default_retry")]
    retry: Retry
}

impl Default for PBFTOutboundConfig {
    #[inline]
    fn default() -> Self {
        PBFTOutboundConfig {
            retry: PBFTOutboundConfig::default_retry()
        }
    }
}

impl PBFTProtoStateConfig {
    #[inline]
    pub fn create(
        outbound: PBFTOutboundConfig,
        view_change_rounds: usize,
        view_change_failures: usize,
        view_change_consecutive_failures: usize,
        view_change_time: Option<Duration>,
        view_change_stall_time: Option<Duration>
    ) -> Self {
        PBFTProtoStateConfig {
            view_change_rounds: view_change_rounds,
            view_change_failures: view_change_failures,
            view_change_consecutive_failures: view_change_consecutive_failures,
            view_change_time: view_change_time,
            view_change_stall_time: view_change_stall_time,
            outbound: outbound
        }
    }

    #[inline]
    pub fn outbound(&self) -> &PBFTOutboundConfig {
        &self.outbound
    }

    #[inline]
    pub fn view_change_rounds(&self) -> usize {
        self.view_change_rounds
    }

    #[inline]
    pub fn view_change_failures(&self) -> usize {
        self.view_change_failures
    }

    #[inline]
    pub fn view_change_consecutive_failures(&self) -> usize {
        self.view_change_consecutive_failures
    }

    #[inline]
    pub fn view_change_time(&self) -> Option<Duration> {
        self.view_change_time
    }

    #[inline]
    pub fn view_change_stall_time(&self) -> Option<Duration> {
        self.view_change_stall_time
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        PBFTOutboundConfig,
        usize,
        usize,
        usize,
        Option<Duration>,
        Option<Duration>
    ) {
        (
            self.outbound,
            self.view_change_rounds,
            self.view_change_failures,
            self.view_change_consecutive_failures,
            self.view_change_time,
            self.view_change_stall_time
        )
    }

    #[inline]
    fn default_view_change_rounds() -> usize {
        256
    }

    #[inline]
    fn default_view_change_failures() -> usize {
        64
    }

    #[inline]
    fn default_view_change_consecutive_failures() -> usize {
        8
    }

    #[inline]
    pub fn default_view_change_time() -> Option<Duration> {
        Some(Duration::from_secs(30))
    }

    #[inline]
    pub fn default_view_change_stall_time() -> Option<Duration> {
        Some(Duration::from_secs(10))
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

    fn default_retry() -> Retry {
        Retry::TERRESTRIAL_NETWORK_DEFAULT
    }
}
