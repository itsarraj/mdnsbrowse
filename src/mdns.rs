//! Real mDNS wire I/O: sends a multicast query (RFC 6762) over a real
//! UDP socket joined to 224.0.0.251:5353, and decodes whatever DNS
//! response packets arrive within the listening window. Wire encoding
//! and decoding is delegated to `hickory-proto` (a real, well-tested
//! DNS codec already used elsewhere in this workspace) — hand-rolling
//! DNS message parsing (including name-compression pointers) would
//! just be reimplementing what that crate already gets right.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use socket2::{Domain, Protocol, Socket, Type};

use crate::records::Record;

pub const MDNS_ADDR_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_PORT: u16 = 5353;

/// Builds a one-shot mDNS query packet for `service_name` (e.g.
/// `_http._tcp.local.` or a specific hostname like `myhost.local.`),
/// requesting `record_type`.
pub fn build_query(service_name: &str, record_type: RecordType) -> Result<Vec<u8>> {
    let name = Name::from_ascii(service_name)
        .with_context(|| format!("'{service_name}' is not a valid DNS name"))?;
    let mut query = Query::new();
    query
        .set_name(name)
        .set_query_type(record_type)
        .set_query_class(DNSClass::IN);

    let mut message = Message::new();
    message
        .set_id(0)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .add_query(query);

    message.to_bytes().context("encoding mDNS query message")
}

/// Opens a UDP socket joined to the mDNS multicast group, sends
/// `query_bytes`, and collects every distinct record parsed out of
/// whatever responses arrive before `timeout` elapses. `interface`
/// picks which local NIC to join/send on for a multi-homed host (the
/// OS's default multicast-interface choice on a box with several NICs
/// and virtual bridges is not always the one an mDNS responder is
/// actually listening on); `None` lets the OS pick.
pub fn browse_raw(
    query_bytes: &[u8],
    timeout: Duration,
    interface: Option<Ipv4Addr>,
) -> Result<Vec<Record>> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("creating UDP socket")?;
    socket
        .set_reuse_address(true)
        .context("setting SO_REUSEADDR")?;
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .context("setting SO_REUSEPORT")?;

    let bind_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT).into();
    socket
        .bind(&bind_addr.into())
        .context("binding UDP socket to port 5353")?;
    let join_iface = interface.unwrap_or(Ipv4Addr::UNSPECIFIED);
    socket
        .join_multicast_v4(&MDNS_ADDR_V4, &join_iface)
        .context("joining the mDNS multicast group 224.0.0.251")?;
    if let Some(iface) = interface {
        socket
            .set_multicast_if_v4(&iface)
            .context("setting outgoing multicast interface")?;
    }
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .context("setting socket read timeout")?;

    let dest: SocketAddr = SocketAddrV4::new(MDNS_ADDR_V4, MDNS_PORT).into();
    socket
        .send_to(query_bytes, &dest.into())
        .context("sending mDNS query")?;

    let mut records = Vec::new();
    let deadline = Instant::now() + timeout;
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 4096];

    while Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((n, _from)) => {
                let bytes: Vec<u8> = buf[..n]
                    .iter()
                    .map(|b| unsafe { b.assume_init() })
                    .collect();
                if let Ok(message) = Message::from_vec(&bytes) {
                    records.extend(extract_records(&message));
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e).context("reading from mDNS socket"),
        }
    }

    Ok(records)
}

fn extract_records(message: &Message) -> Vec<Record> {
    message
        .answers()
        .iter()
        .chain(message.additionals())
        .filter_map(|record| {
            let name = record.name().to_utf8();
            match record.data()? {
                RData::PTR(ptr) => Some(Record::Ptr {
                    name,
                    target: ptr.0.to_utf8(),
                }),
                RData::SRV(srv) => Some(Record::Srv {
                    name,
                    target: srv.target().to_utf8(),
                    port: srv.port(),
                }),
                RData::TXT(txt) => {
                    let entries = txt
                        .iter()
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                        .collect();
                    Some(Record::Txt { name, entries })
                }
                RData::A(a) => Some(Record::Address {
                    name,
                    addr: IpAddr::V4(a.0),
                }),
                RData::AAAA(aaaa) => Some(Record::Address {
                    name,
                    addr: IpAddr::V6(aaaa.0),
                }),
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_encodes_a_valid_non_empty_packet() {
        let bytes = build_query("_http._tcp.local.", RecordType::PTR).unwrap();
        assert!(!bytes.is_empty());
        // A valid DNS message always starts with a 2-byte transaction ID
        // followed by flags; our query sets id=0.
        assert_eq!(&bytes[0..2], &[0x00, 0x00]);
    }

    #[test]
    fn build_query_round_trips_through_the_real_decoder() {
        let bytes = build_query("myhost.local.", RecordType::A).unwrap();
        let decoded = Message::from_vec(&bytes).unwrap();
        assert_eq!(decoded.queries().len(), 1);
        assert_eq!(decoded.queries()[0].name().to_utf8(), "myhost.local.");
        assert_eq!(decoded.queries()[0].query_type(), RecordType::A);
    }

    #[test]
    fn build_query_rejects_an_invalid_name() {
        assert!(build_query("not a valid dns name with spaces", RecordType::PTR).is_err());
    }
}
