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

//! Protocol messages.
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;

use constellation_common::codec::per::PERCodec;
use constellation_common::hashid::HashID;
use constellation_consensus_common::round::RoundMsg;

pub use crate::generated::msgs::PbftContent;
pub use crate::generated::msgs::PbftMsg;
pub use crate::generated::req::PbftAction;
pub use crate::generated::req::PbftMember;
pub use crate::generated::req::PbftRequest;
pub use crate::generated::req::PbftView;

impl Eq for PbftContent {}
impl Eq for PbftMsg {}
impl Eq for PbftRequest {}

pub type PBFTMsgPERCodec = PERCodec<PbftMsg, 8348>;

impl<RoundID> RoundMsg<RoundID> for PbftMsg
where
    RoundID: Clone + Display + Ord + From<u128> + Into<u128>
{
    type Payload = PbftContent;

    #[inline]
    fn create(
        round: RoundID,
        payload: Self::Payload
    ) -> Self {
        let round: u128 = round.into();
        let round = vec![
            (round >> 120) as u8,
            (round >> 112) as u8,
            (round >> 104) as u8,
            (round >> 96) as u8,
            (round >> 88) as u8,
            (round >> 80) as u8,
            (round >> 72) as u8,
            (round >> 64) as u8,
            (round >> 56) as u8,
            (round >> 48) as u8,
            (round >> 40) as u8,
            (round >> 32) as u8,
            (round >> 24) as u8,
            (round >> 16) as u8,
            (round >> 8) as u8,
            round as u8,
        ];

        PbftMsg {
            round: round,
            content: payload
        }
    }

    #[inline]
    fn round_id(&self) -> RoundID {
        let mut out = self.round[15] as u128;

        out |= (self.round[14] as u128) << 8;
        out |= (self.round[13] as u128) << 16;
        out |= (self.round[12] as u128) << 24;
        out |= (self.round[11] as u128) << 32;
        out |= (self.round[10] as u128) << 40;
        out |= (self.round[9] as u128) << 48;
        out |= (self.round[8] as u128) << 56;
        out |= (self.round[7] as u128) << 64;
        out |= (self.round[6] as u128) << 72;
        out |= (self.round[5] as u128) << 80;
        out |= (self.round[4] as u128) << 88;
        out |= (self.round[3] as u128) << 96;
        out |= (self.round[2] as u128) << 104;
        out |= (self.round[1] as u128) << 112;
        out |= (self.round[0] as u128) << 120;

        out.into()
    }

    #[inline]
    fn payload(&self) -> &Self::Payload {
        &self.content
    }

    #[inline]
    fn take(self) -> (RoundID, Self::Payload) {
        (self.round_id(), self.content)
    }
}

impl Display for PbftAction {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            PbftAction::Admit => write!(f, "admit"),
            PbftAction::Evict => write!(f, "evict")
        }
    }
}

impl Display for PbftMember {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{} ", self.action)?;

        for byte in self.id.iter() {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl PbftRequest {
    #[inline]
    pub fn view_change<ID>(id: &ID) -> Self
    where
        ID: HashID {
        PbftRequest::View(PbftView {
            id: id.bytes().to_vec()
        })
    }
}

impl Display for PbftRequest {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            PbftRequest::Payload(bytes) => {
                write!(f, "payload: ")?;

                for byte in bytes {
                    write!(f, "{:02x}", byte)?;
                }

                Ok(())
            }
            PbftRequest::Members(members) => {
                let mut first = true;

                write!(f, "member update:")?;

                for member in members {
                    if first {
                        first = false;

                        write!(f, " {}", member)?;
                    } else {
                        write!(f, ", {}", member)?;
                    }
                }

                Ok(())
            }
            PbftRequest::View(PbftView { id }) => {
                write!(f, "view change, new leader: ")?;

                for byte in id {
                    write!(f, "{:02x}", byte)?;
                }

                Ok(())
            }
        }
    }
}

#[cfg(test)]
use asn1rs::prelude::Null;
#[cfg(test)]
use asn1rs::prelude::Reader;
#[cfg(test)]
use asn1rs::prelude::Writer;
#[cfg(test)]
use asn1rs::syn::io::UperReader;
#[cfg(test)]
use asn1rs::syn::io::UperWriter;
#[cfg(test)]
use constellation_common::codec::Codec;
#[cfg(test)]
use constellation_common::codec::DatagramCodec;

#[cfg(test)]
use crate::generated::msgs::PbftAckState;
#[cfg(test)]
use crate::generated::msgs::PbftStateUpdate;
#[cfg(test)]
use crate::generated::msgs::PbftUpdateAck;

#[cfg(test)]
const UDP_MTU: usize = 1472;

#[cfg(test)]
fn make_payload_request() -> PbftRequest {
    let mut payload = vec![0; 1024];

    for i in 0..1024 {
        payload[i] = i as u8 / 4;
    }

    PbftRequest::Payload(payload)
}

#[cfg(test)]
fn make_members_request() -> PbftRequest {
    let mut members = Vec::with_capacity(16);

    for i in 0..16 {
        let id = vec![i as u8; 64];
        let action = if i % 2 == 1 {
            PbftAction::Admit
        } else {
            PbftAction::Evict
        };

        members.push(PbftMember {
            id: id,
            action: action
        })
    }

    PbftRequest::Members(members)
}

#[test]
fn test_request_payload() {
    let req = make_payload_request();
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftRequest>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_request_members() {
    let req = make_members_request();
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftRequest>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_request_view() {
    let req = PbftRequest::View(PbftView { id: vec![0; 64] });
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftRequest>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_payload() {
    let req =
        PbftContent::Update(PbftStateUpdate::Prepare(make_payload_request()));
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_members() {
    let req =
        PbftContent::Update(PbftStateUpdate::Prepare(make_members_request()));
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_view() {
    let req = PbftContent::Update(PbftStateUpdate::Prepare(PbftRequest::View(
        PbftView { id: vec![0; 64] }
    )));
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_payload() {
    let req =
        PbftContent::Update(PbftStateUpdate::Commit(make_payload_request()));
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_members() {
    let req =
        PbftContent::Update(PbftStateUpdate::Commit(make_members_request()));
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_view() {
    let req = PbftContent::Update(PbftStateUpdate::Commit(PbftRequest::View(
        PbftView { id: vec![0; 64] }
    )));
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_payload() {
    let req =
        PbftContent::Update(PbftStateUpdate::Complete(make_payload_request()));
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_members() {
    let req =
        PbftContent::Update(PbftStateUpdate::Complete(make_members_request()));
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_view() {
    let req = PbftContent::Update(PbftStateUpdate::Complete(
        PbftRequest::View(PbftView { id: vec![0; 64] })
    ));
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_fail() {
    let req = PbftContent::Update(PbftStateUpdate::Fail(Null));
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_ack_prepare() {
    let req = PbftContent::Ack(PbftAckState::Prepare);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_ack_commit() {
    let req = PbftContent::Ack(PbftAckState::Commit);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_ack_complete() {
    let req = PbftContent::Ack(PbftAckState::Complete);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_ack_fail() {
    let req = PbftContent::Ack(PbftAckState::Fail);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_payload_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_payload_request()),
        ack: PbftAckState::Prepare
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_payload_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_payload_request()),
        ack: PbftAckState::Commit
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_payload_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_payload_request()),
        ack: PbftAckState::Complete
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_payload_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_payload_request()),
        ack: PbftAckState::Fail
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_members_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_members_request()),
        ack: PbftAckState::Prepare
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_members_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_members_request()),
        ack: PbftAckState::Commit
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_members_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_members_request()),
        ack: PbftAckState::Complete
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_members_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_members_request()),
        ack: PbftAckState::Fail
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_view_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Prepare
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_view_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Commit
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_view_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Complete
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_prepare_view_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Fail
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_payload_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_payload_request()),
        ack: PbftAckState::Prepare
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_payload_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_payload_request()),
        ack: PbftAckState::Commit
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_payload_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_payload_request()),
        ack: PbftAckState::Complete
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_payload_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_payload_request()),
        ack: PbftAckState::Fail
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_members_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_members_request()),
        ack: PbftAckState::Prepare
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_members_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_members_request()),
        ack: PbftAckState::Commit
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_members_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_members_request()),
        ack: PbftAckState::Complete
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_members_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_members_request()),
        ack: PbftAckState::Fail
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_view_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Prepare
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_view_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Commit
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_view_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Complete
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_commit_view_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Fail
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_payload_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_payload_request()),
        ack: PbftAckState::Prepare
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_payload_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_payload_request()),
        ack: PbftAckState::Commit
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_payload_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_payload_request()),
        ack: PbftAckState::Complete
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_payload_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_payload_request()),
        ack: PbftAckState::Fail
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_members_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_members_request()),
        ack: PbftAckState::Prepare
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_members_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_members_request()),
        ack: PbftAckState::Commit
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_members_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_members_request()),
        ack: PbftAckState::Complete
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_members_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_members_request()),
        ack: PbftAckState::Fail
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_view_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Prepare
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_view_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Commit
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_view_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Complete
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_complete_view_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Fail
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_fail_view_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Fail(Null),
        ack: PbftAckState::Prepare
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_fail_view_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Fail(Null),
        ack: PbftAckState::Commit
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_fail_view_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Fail(Null),
        ack: PbftAckState::Complete
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_update_fail_view_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Fail(Null),
        ack: PbftAckState::Fail
    };
    let req = PbftContent::UpdateAck(update_ack);
    let mut writer = UperWriter::default();

    writer.write(&req).expect("Expected success");

    let nbits = writer.bit_len();
    let bytes = writer.into_bytes_vec();

    assert!(bytes.len() <= UDP_MTU);

    let mut reader = UperReader::from((&bytes[..], nbits));
    let result = reader.read::<PbftContent>().unwrap();

    assert_eq!(req, result);
}

#[test]
fn test_msg_codec_update_prepare_payload() {
    let msg = PbftMsg::create(
        0xff00,
        PbftContent::Update(PbftStateUpdate::Prepare(make_payload_request()))
    );
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_members() {
    let msg = PbftMsg::create(
        0xff00,
        PbftContent::Update(PbftStateUpdate::Prepare(make_members_request()))
    );
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_view() {
    let msg = PbftMsg::create(
        0xff00,
        PbftContent::Update(PbftStateUpdate::Prepare(PbftRequest::View(
            PbftView { id: vec![0; 64] }
        )))
    );
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_payload() {
    let msg = PbftMsg::create(
        0xff00,
        PbftContent::Update(PbftStateUpdate::Commit(make_payload_request()))
    );
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_members() {
    let msg = PbftMsg::create(
        0xff00,
        PbftContent::Update(PbftStateUpdate::Commit(make_members_request()))
    );
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_view() {
    let msg = PbftMsg::create(
        0xff00,
        PbftContent::Update(PbftStateUpdate::Commit(PbftRequest::View(
            PbftView { id: vec![0; 64] }
        )))
    );
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_payload() {
    let msg = PbftMsg::create(
        0xff00,
        PbftContent::Update(PbftStateUpdate::Complete(make_payload_request()))
    );
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_members() {
    let msg = PbftMsg::create(
        0xff00,
        PbftContent::Update(PbftStateUpdate::Complete(make_members_request()))
    );
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_view() {
    let msg = PbftMsg::create(
        0xff00,
        PbftContent::Update(PbftStateUpdate::Complete(PbftRequest::View(
            PbftView { id: vec![0; 64] }
        )))
    );
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_fail() {
    let msg = PbftMsg::create(
        0xff00,
        PbftContent::Update(PbftStateUpdate::Fail(Null))
    );
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_ack_prepare() {
    let msg = PbftMsg::create(0xff00, PbftContent::Ack(PbftAckState::Prepare));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_ack_commit() {
    let msg = PbftMsg::create(0xff00, PbftContent::Ack(PbftAckState::Commit));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_ack_complete() {
    let msg = PbftMsg::create(0xff00, PbftContent::Ack(PbftAckState::Complete));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_ack_fail() {
    let msg = PbftMsg::create(0xff00, PbftContent::Ack(PbftAckState::Fail));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_payload_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_payload_request()),
        ack: PbftAckState::Prepare
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_payload_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_payload_request()),
        ack: PbftAckState::Commit
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_payload_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_payload_request()),
        ack: PbftAckState::Complete
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_payload_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_payload_request()),
        ack: PbftAckState::Fail
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_members_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_members_request()),
        ack: PbftAckState::Prepare
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_members_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_members_request()),
        ack: PbftAckState::Commit
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_members_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_members_request()),
        ack: PbftAckState::Complete
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_members_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(make_members_request()),
        ack: PbftAckState::Fail
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_view_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Prepare
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_view_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Commit
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_view_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Complete
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_prepare_view_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Prepare(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Fail
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_payload_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_payload_request()),
        ack: PbftAckState::Prepare
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_payload_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_payload_request()),
        ack: PbftAckState::Commit
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_payload_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_payload_request()),
        ack: PbftAckState::Complete
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_payload_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_payload_request()),
        ack: PbftAckState::Fail
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_members_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_members_request()),
        ack: PbftAckState::Prepare
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_members_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_members_request()),
        ack: PbftAckState::Commit
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_members_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_members_request()),
        ack: PbftAckState::Complete
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_members_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(make_members_request()),
        ack: PbftAckState::Fail
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_view_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Prepare
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_view_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Commit
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_view_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Complete
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_commit_view_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Commit(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Fail
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_payload_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_payload_request()),
        ack: PbftAckState::Prepare
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_payload_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_payload_request()),
        ack: PbftAckState::Commit
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_payload_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_payload_request()),
        ack: PbftAckState::Fail
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_members_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_members_request()),
        ack: PbftAckState::Prepare
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_members_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_members_request()),
        ack: PbftAckState::Commit
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_members_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_members_request()),
        ack: PbftAckState::Complete
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_members_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(make_members_request()),
        ack: PbftAckState::Fail
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_view_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Prepare
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_view_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Commit
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_view_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Complete
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_complete_view_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Complete(PbftRequest::View(PbftView {
            id: vec![0; 64]
        })),
        ack: PbftAckState::Fail
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_fail_view_ack_prepare() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Fail(Null),
        ack: PbftAckState::Prepare
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_fail_view_ack_commit() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Fail(Null),
        ack: PbftAckState::Commit
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_fail_view_ack_complete() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Fail(Null),
        ack: PbftAckState::Complete
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_msg_codec_update_fail_view_ack_fail() {
    let update_ack = PbftUpdateAck {
        update: PbftStateUpdate::Fail(Null),
        ack: PbftAckState::Fail
    };
    let msg = PbftMsg::create(0xff00, PbftContent::UpdateAck(update_ack));
    let mut codec = PBFTMsgPERCodec::create(()).unwrap();
    let mut buf = [0; PBFTMsgPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&msg, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(msg, actual);
    assert_eq!(nencoded, nbytes);
}
