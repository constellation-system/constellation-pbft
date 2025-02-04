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

//! Implementation of the Castro-Liskov PBFT consensus protocol.
//!
//! This crate provides an implementation of the Castro-Liskov PBFT
//! consensus protocol usable in the Constellation distributed systems
//! platfrom.  The Castro-Liskov protocol is described by the paper
//! [Practical Byzantine Fault
//! Tolerance](https://dl.acm.org/doi/10.5555/296806.296824).  It
//! provide a consensus protocol resilient against a Byzantine
//! Adversary who controls up to but not including 1/3rd of the
//! parties in the consensus pool.
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
#![allow(clippy::redundant_field_names)]

pub mod config;
pub mod msgs;
pub mod proto;
pub mod state;

#[allow(clippy::all)]
#[rustfmt::skip]
mod generated;
mod outbound;

#[cfg(test)]
use std::sync::Once;

#[cfg(test)]
use log::LevelFilter;

#[cfg(test)]
static INIT: Once = Once::new();

#[cfg(test)]
fn init() {
    INIT.call_once(|| {
        env_logger::builder()
            .is_test(true)
            .filter_level(LevelFilter::Trace)
            .init()
    })
}
