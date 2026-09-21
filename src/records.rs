//! Pure, protocol-library-agnostic record model and service-instance
//! aggregation. `mdns.rs` converts real `hickory_proto` records into
//! [`Record`] values; everything here is plain data plus pure
//! functions, independent of sockets or the DNS codec.

use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// A PTR record: `name` is the service type (e.g.
    /// `_http._tcp.local`), `target` is a specific instance's full name.
    Ptr { name: String, target: String },
    /// An SRV record: `name` is the instance's full name, `target` is
    /// the hostname that owns it, `port` is the service port.
    Srv {
        name: String,
        target: String,
        port: u16,
    },
    /// A TXT record: `name` is the instance's full name, `entries` are
    /// the raw `key=value` (or bare) strings it carries.
    Txt { name: String, entries: Vec<String> },
    /// An A/AAAA record: `name` is a hostname, `addr` its IP.
    Address { name: String, addr: IpAddr },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceInstance {
    pub name: String,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub addrs: Vec<IpAddr>,
    pub txt: Vec<String>,
}

/// Joins a flat list of records (as would arrive scattered across one
/// or more mDNS response packets) into per-instance service records:
/// PTR gives the instance names, SRV gives host+port, TXT gives
/// metadata, and A/AAAA (matched by the SRV target hostname) gives
/// resolved addresses.
pub fn aggregate(records: &[Record]) -> Vec<ServiceInstance> {
    let mut instance_names: Vec<String> = records
        .iter()
        .filter_map(|r| match r {
            Record::Ptr { target, .. } => Some(target.clone()),
            _ => None,
        })
        .collect();
    instance_names.sort();
    instance_names.dedup();

    instance_names
        .into_iter()
        .map(|name| {
            let srv = records.iter().find_map(|r| match r {
                Record::Srv {
                    name: n,
                    target,
                    port,
                } if *n == name => Some((target.clone(), *port)),
                _ => None,
            });
            let txt: Vec<String> = records
                .iter()
                .find_map(|r| match r {
                    Record::Txt { name: n, entries } if *n == name => Some(entries.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            let (host, port) = match srv {
                Some((h, p)) => (Some(h), Some(p)),
                None => (None, None),
            };
            let addrs: Vec<IpAddr> = host
                .as_ref()
                .map(|h| {
                    records
                        .iter()
                        .filter_map(|r| match r {
                            Record::Address { name: n, addr } if n == h => Some(*addr),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();

            ServiceInstance {
                name,
                host,
                port,
                addrs,
                txt,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_records() -> Vec<Record> {
        vec![
            Record::Ptr {
                name: "_http._tcp.local".into(),
                target: "My Printer._http._tcp.local".into(),
            },
            Record::Srv {
                name: "My Printer._http._tcp.local".into(),
                target: "printer.local".into(),
                port: 631,
            },
            Record::Txt {
                name: "My Printer._http._tcp.local".into(),
                entries: vec!["path=/ipp".into(), "rp=printer".into()],
            },
            Record::Address {
                name: "printer.local".into(),
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            },
        ]
    }

    #[test]
    fn aggregate_joins_ptr_srv_txt_and_address_into_one_instance() {
        let instances = aggregate(&sample_records());
        assert_eq!(instances.len(), 1);
        let inst = &instances[0];
        assert_eq!(inst.name, "My Printer._http._tcp.local");
        assert_eq!(inst.host.as_deref(), Some("printer.local"));
        assert_eq!(inst.port, Some(631));
        assert_eq!(inst.addrs, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))]);
        assert_eq!(
            inst.txt,
            vec!["path=/ipp".to_string(), "rp=printer".to_string()]
        );
    }

    #[test]
    fn aggregate_handles_multiple_distinct_instances() {
        let mut records = sample_records();
        records.push(Record::Ptr {
            name: "_http._tcp.local".into(),
            target: "Other Printer._http._tcp.local".into(),
        });
        let instances = aggregate(&records);
        assert_eq!(instances.len(), 2);
        assert!(instances
            .iter()
            .any(|i| i.name == "Other Printer._http._tcp.local"));
    }

    #[test]
    fn aggregate_returns_empty_for_no_records() {
        assert!(aggregate(&[]).is_empty());
    }

    #[test]
    fn aggregate_gives_instance_with_no_srv_no_host_or_port() {
        let records = vec![Record::Ptr {
            name: "_http._tcp.local".into(),
            target: "Ghost._http._tcp.local".into(),
        }];
        let instances = aggregate(&records);
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].host, None);
        assert_eq!(instances[0].port, None);
        assert!(instances[0].addrs.is_empty());
    }

    #[test]
    fn aggregate_deduplicates_repeated_ptr_records() {
        // Real mDNS responders often repeat PTR announcements across packets.
        let mut records = sample_records();
        records.push(Record::Ptr {
            name: "_http._tcp.local".into(),
            target: "My Printer._http._tcp.local".into(),
        });
        let instances = aggregate(&records);
        assert_eq!(instances.len(), 1);
    }

    #[test]
    fn aggregate_only_attaches_addresses_matching_the_srv_target_hostname() {
        let mut records = sample_records();
        records.push(Record::Address {
            name: "unrelated-host.local".into(),
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        });
        let instances = aggregate(&records);
        assert_eq!(instances[0].addrs.len(), 1);
        assert_eq!(
            instances[0].addrs[0],
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))
        );
    }
}
