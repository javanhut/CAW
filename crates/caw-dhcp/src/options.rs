//! The DHCP option area: a TLV list living after the magic cookie.
//!
//! Only the options caw acts on get their own variant. Everything else
//! survives decoding as [`DhcpOption::Other`] rather than being dropped, so a
//! message can be inspected without this module being a complete RFC 2132
//! implementation.

use std::net::Ipv4Addr;

use crate::Error;

// Option codes. RFC 2132 defines around eighty; these are the ones that
// change what caw does.
pub const OPT_PAD: u8 = 0;
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS: u8 = 6;
pub const OPT_HOSTNAME: u8 = 12;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_OVERLOAD: u8 = 52;
pub const OPT_MESSAGE_TYPE: u8 = 53;
pub const OPT_SERVER_ID: u8 = 54;
pub const OPT_PARAM_REQUEST: u8 = 55;
pub const OPT_T1: u8 = 58;
pub const OPT_T2: u8 = 59;
pub const OPT_CLIENT_ID: u8 = 61;
pub const OPT_END: u8 = 255;

/// Option 52 bits: which BOOTP fields have been repurposed to carry options.
pub const OVERLOAD_FILE: u8 = 1;
pub const OVERLOAD_SNAME: u8 = 2;

/// Option 53. `Other` keeps message types caw does not implement decodable
/// instead of turning the whole datagram into an error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    Other(u8),
}

impl MessageType {
    pub fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            other => Self::Other(other),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
            Self::Other(code) => code,
        }
    }
}

/// One decoded option.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    Dns(Vec<Ipv4Addr>),
    HostName(String),
    RequestedIp(Ipv4Addr),
    LeaseTime(u32),
    MessageType(MessageType),
    ServerId(Ipv4Addr),
    ParameterRequest(Vec<u8>),
    /// Option 58, the renewal timer.
    T1(u32),
    /// Option 59, the rebinding timer.
    T2(u32),
    /// Option 61. The first byte is the hardware type, so an Ethernet client
    /// id is `01` followed by the MAC.
    ClientId(Vec<u8>),
    Other {
        code: u8,
        data: Vec<u8>,
    },
}

impl DhcpOption {
    pub fn code(&self) -> u8 {
        match self {
            Self::SubnetMask(_) => OPT_SUBNET_MASK,
            Self::Router(_) => OPT_ROUTER,
            Self::Dns(_) => OPT_DNS,
            Self::HostName(_) => OPT_HOSTNAME,
            Self::RequestedIp(_) => OPT_REQUESTED_IP,
            Self::LeaseTime(_) => OPT_LEASE_TIME,
            Self::MessageType(_) => OPT_MESSAGE_TYPE,
            Self::ServerId(_) => OPT_SERVER_ID,
            Self::ParameterRequest(_) => OPT_PARAM_REQUEST,
            Self::T1(_) => OPT_T1,
            Self::T2(_) => OPT_T2,
            Self::ClientId(_) => OPT_CLIENT_ID,
            Self::Other { code, .. } => *code,
        }
    }

    fn decode(code: u8, data: &[u8]) -> Result<Self, Error> {
        Ok(match code {
            OPT_SUBNET_MASK => Self::SubnetMask(ipv4(data)?),
            OPT_ROUTER => Self::Router(ipv4_list(data)?),
            OPT_DNS => Self::Dns(ipv4_list(data)?),
            // Lossy because a stray byte in the name the server assigned us is
            // not a reason to throw away an otherwise usable lease.
            OPT_HOSTNAME => Self::HostName(String::from_utf8_lossy(data).into_owned()),
            OPT_REQUESTED_IP => Self::RequestedIp(ipv4(data)?),
            OPT_LEASE_TIME => Self::LeaseTime(be_u32(data)?),
            OPT_MESSAGE_TYPE => match data {
                [code] => Self::MessageType(MessageType::from_code(*code)),
                _ => return Err(Error::Malformed),
            },
            OPT_SERVER_ID => Self::ServerId(ipv4(data)?),
            OPT_PARAM_REQUEST => Self::ParameterRequest(data.to_vec()),
            OPT_T1 => Self::T1(be_u32(data)?),
            OPT_T2 => Self::T2(be_u32(data)?),
            OPT_CLIENT_ID => Self::ClientId(data.to_vec()),
            code => Self::Other {
                code,
                data: data.to_vec(),
            },
        })
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::SubnetMask(a) | Self::RequestedIp(a) | Self::ServerId(a) => {
                tlv(out, self.code(), &a.octets())
            }
            Self::Router(list) | Self::Dns(list) => {
                let mut bytes = Vec::with_capacity(list.len() * 4);
                for addr in list {
                    bytes.extend_from_slice(&addr.octets());
                }
                tlv(out, self.code(), &bytes)
            }
            Self::HostName(name) => tlv(out, self.code(), name.as_bytes()),
            Self::LeaseTime(v) | Self::T1(v) | Self::T2(v) => {
                tlv(out, self.code(), &v.to_be_bytes())
            }
            Self::MessageType(mt) => tlv(out, self.code(), &[mt.code()]),
            Self::ParameterRequest(data) | Self::ClientId(data) => tlv(out, self.code(), data),
            Self::Other { code, data } => tlv(out, *code, data),
        }
    }
}

/// Append one option. A TLV length is a single byte, so anything longer is
/// truncated rather than encoded with a length that wraps.
fn tlv(out: &mut Vec<u8>, code: u8, data: &[u8]) {
    let len = data.len().min(u8::MAX as usize);
    out.push(code);
    out.push(len as u8);
    out.extend_from_slice(&data[..len]);
}

/// Decode a TLV area onto `out`, returning the accumulated option-overload
/// bits so the caller knows whether `file` and `sname` hold options too.
///
/// Stops at the end option; a region that simply runs out is also accepted,
/// because trailing padding is routinely trimmed in transit. A declared length
/// that reaches past the end is a genuinely broken message and is rejected.
pub(crate) fn decode_into(buf: &[u8], out: &mut Vec<DhcpOption>) -> Result<u8, Error> {
    let mut overload = 0;
    let mut i = 0;
    while i < buf.len() {
        match buf[i] {
            // Pad has no length byte; it exists to align what follows.
            OPT_PAD => {
                i += 1;
                continue;
            }
            OPT_END => return Ok(overload),
            _ => {}
        }
        let code = buf[i];
        let len = *buf.get(i + 1).ok_or(Error::Malformed)? as usize;
        let data = buf.get(i + 2..i + 2 + len).ok_or(Error::Malformed)?;
        i += 2 + len;

        if code == OPT_OVERLOAD {
            match data {
                [bits] => overload |= *bits,
                _ => return Err(Error::Malformed),
            }
            continue;
        }
        out.push(DhcpOption::decode(code, data)?);
    }
    Ok(overload)
}

/// Encode a TLV area, terminated by the end option.
pub(crate) fn encode_all(options: &[DhcpOption], out: &mut Vec<u8>) {
    for opt in options {
        opt.encode(out);
    }
    out.push(OPT_END);
}

fn ipv4(data: &[u8]) -> Result<Ipv4Addr, Error> {
    match data {
        [a, b, c, d] => Ok(Ipv4Addr::new(*a, *b, *c, *d)),
        _ => Err(Error::Malformed),
    }
}

/// One or more addresses. An empty list is malformed: the option would be
/// carrying nothing.
fn ipv4_list(data: &[u8]) -> Result<Vec<Ipv4Addr>, Error> {
    if data.is_empty() || !data.len().is_multiple_of(4) {
        return Err(Error::Malformed);
    }
    Ok(data
        .as_chunks::<4>()
        .0
        .iter()
        .copied()
        .map(Ipv4Addr::from)
        .collect())
}

fn be_u32(data: &[u8]) -> Result<u32, Error> {
    match data {
        [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
        _ => Err(Error::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_variant() {
        let options = vec![
            DhcpOption::MessageType(MessageType::Request),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]),
            DhcpOption::Dns(vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)]),
            DhcpOption::HostName("corvus".to_owned()),
            DhcpOption::RequestedIp(Ipv4Addr::new(192, 168, 1, 24)),
            DhcpOption::LeaseTime(43_200),
            DhcpOption::ServerId(Ipv4Addr::new(192, 168, 1, 1)),
            DhcpOption::ParameterRequest(vec![1, 3, 6]),
            DhcpOption::T1(21_600),
            DhcpOption::T2(37_800),
            DhcpOption::ClientId(vec![1, 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee]),
            DhcpOption::Other {
                code: 82,
                data: vec![0xde, 0xad],
            },
        ];
        let mut bytes = Vec::new();
        encode_all(&options, &mut bytes);

        let mut decoded = Vec::new();
        assert_eq!(decode_into(&bytes, &mut decoded).unwrap(), 0);
        assert_eq!(decoded, options);
    }

    #[test]
    fn skips_pad_and_stops_at_end() {
        // Pad, message type, pad, end, then bytes that must never be read.
        let bytes = [OPT_PAD, 53, 1, 1, OPT_PAD, OPT_END, 0xff, 0xff, 0xff];
        let mut out = Vec::new();
        decode_into(&bytes, &mut out).unwrap();
        assert_eq!(out, vec![DhcpOption::MessageType(MessageType::Discover)]);
    }

    #[test]
    fn accepts_an_area_that_ends_without_the_end_option() {
        // Trailing padding is routinely trimmed in transit.
        let bytes = [53, 1, 5];
        let mut out = Vec::new();
        decode_into(&bytes, &mut out).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn rejects_length_past_the_end() {
        let mut out = Vec::new();
        assert_eq!(decode_into(&[53, 9, 5], &mut out), Err(Error::Malformed));
        // A code with no length byte at all.
        assert_eq!(decode_into(&[53], &mut out), Err(Error::Malformed));
    }

    #[test]
    fn rejects_wrong_length_for_a_fixed_option() {
        let mut out = Vec::new();
        // A three-byte subnet mask.
        assert_eq!(
            decode_into(&[1, 3, 255, 255, 255], &mut out),
            Err(Error::Malformed)
        );
        // A router list that is not a whole number of addresses.
        assert_eq!(
            decode_into(&[3, 5, 1, 2, 3, 4, 5], &mut out),
            Err(Error::Malformed)
        );
        // A two-byte message type.
        assert_eq!(decode_into(&[53, 2, 1, 1], &mut out), Err(Error::Malformed));
    }

    #[test]
    fn overload_is_reported_not_emitted() {
        let bytes = [OPT_OVERLOAD, 1, 3, 53, 1, 5, OPT_END];
        let mut out = Vec::new();
        let overload = decode_into(&bytes, &mut out).unwrap();
        assert_eq!(overload, OVERLOAD_FILE | OVERLOAD_SNAME);
        assert_eq!(out, vec![DhcpOption::MessageType(MessageType::Ack)]);
    }

    #[test]
    fn truncations_never_panic() {
        let mut bytes = Vec::new();
        encode_all(
            &[
                DhcpOption::MessageType(MessageType::Ack),
                DhcpOption::Dns(vec![Ipv4Addr::new(1, 1, 1, 1)]),
            ],
            &mut bytes,
        );
        for n in 0..bytes.len() {
            let mut out = Vec::new();
            let _ = decode_into(&bytes[..n], &mut out);
        }
    }
}
