use cidr::IpCidr;
use std::net::IpAddr;
use std::str::FromStr;

fn get_octets(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(addr) => addr.octets().to_vec(),
        IpAddr::V6(addr) => addr.octets().to_vec(),
    }
}

/// IP is an abstraction over one ip address (IpAddr) or range of ips (netowrk, aka IpCidr)
#[derive(Debug, PartialEq)]
pub struct IP {
    addr: IpAddr,
    cidr: Option<IpCidr>,
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    IpAddrParseError(std::net::AddrParseError),
    CidrParseError(cidr::errors::NetworkParseError),
}

impl FromStr for IP {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<IP, Self::Err> {
        match s.split_once('/') {
            Some((ip, _)) => {
                let cidr = IpCidr::from_str(s).map_err(ParseError::CidrParseError)?;
                Ok(IP {
                    addr: IpAddr::from_str(ip).map_err(ParseError::IpAddrParseError)?,
                    cidr: Some(cidr),
                })
            }
            None => Ok(IP {
                addr: IpAddr::from_str(s).map_err(ParseError::IpAddrParseError)?,
                cidr: None,
            }),
        }
    }
}

impl IP {
    /// Check if passed ip in in subset of ips range represented by this IP
    pub fn contains(&self, ip: &IP) -> bool {
        match (self.cidr, ip.cidr) {
            (Some(cidr), None) => cidr.contains(&ip.addr),
            _ => false,
        }
    }

    pub fn network_length(&self) -> Option<u8> {
        self.cidr.as_ref().map(|cidr| cidr.network_length())
    }

    pub fn addr(&self) -> String {
        self.addr.to_string()
    }

    pub fn octets(&self) -> Vec<u8> {
        get_octets(&self.addr)
    }

    /// network mask: an pseudo address which has the first `network
    /// length` bits set to 1 and the remaining to 0.
    pub fn mask(&self) -> Option<Vec<u8>> {
        self.cidr.as_ref().map(|cidr| get_octets(&cidr.mask()))
    }

    pub fn is_v6(&self) -> bool {
        self.addr.is_ipv6()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_v4() {
        assert_eq!(
            IP::from_str("192.168.56.0").unwrap(),
            IP {
                addr: IpAddr::from_str("192.168.56.0").unwrap(),
                cidr: None
            },
        );

        assert_eq!(
            IP::from_str("192.168.56.0/24").unwrap(),
            IP {
                addr: IpAddr::from_str("192.168.56.0").unwrap(),
                cidr: Some(IpCidr::from_str("192.168.56.0/24").unwrap()),
            }
        );

        assert!(
            match IP::from_str("test") {
                Err(ParseError::IpAddrParseError(_)) => true,
                _ => false,
            },
            "Should be IpAddrParseError"
        );

        assert!(
            match IP::from_str("123") {
                Err(ParseError::IpAddrParseError(_)) => true,
                _ => false,
            },
            "Should be IpAddrParseError"
        );

        assert!(
            match IP::from_str("192.168.56.0/test") {
                Err(ParseError::CidrParseError(_)) => true,
                _ => false,
            },
            "Should be CidrParseError"
        );

        assert!(
            match IP::from_str("192.168.56.0/100000000") {
                Err(ParseError::CidrParseError(_)) => true,
                _ => false,
            },
            "Should be CidrParseError"
        );

        assert!(
            match IP::from_str("192.168.56.0/") {
                Err(ParseError::CidrParseError(_)) => true,
                _ => false,
            },
            "Should be CidrParseError"
        );
    }

    #[test]
    fn test_parse_ip_v6() {
        assert_eq!(
            IP::from_str("2001:0db8:85a3:0000:0000:8a2e:0370:7334").unwrap(),
            IP {
                addr: IpAddr::from_str("2001:0db8:85a3:0000:0000:8a2e:0370:7334").unwrap(),
                cidr: None
            },
        );

        assert_eq!(
            IP::from_str("::1234:5678").unwrap(),
            IP {
                addr: IpAddr::from_str("::1234:5678").unwrap(),
                cidr: None
            },
        );

        assert_eq!(
            IP::from_str("2001:db8::").unwrap(),
            IP {
                addr: IpAddr::from_str("2001:db8::").unwrap(),
                cidr: None
            },
        );

        assert_eq!(
            IP::from_str("2001:1111:2222:3333::/64").unwrap(),
            IP {
                addr: IpAddr::from_str("2001:1111:2222:3333::").unwrap(),
                cidr: Some(IpCidr::from_str("2001:1111:2222:3333::/64").unwrap()),
            },
        );

        assert!(
            match IP::from_str("2001:1111:2222:3333::/test") {
                Err(ParseError::CidrParseError(_)) => true,
                _ => false,
            },
            "Should be CidrParseError"
        );

        assert!(
            match IP::from_str("2001:1111:2222:3333::/123312312312") {
                Err(ParseError::CidrParseError(_)) => true,
                _ => false,
            },
            "Should be CidrParseError"
        );

        assert!(
            match IP::from_str("2001:1111:2222:3333::/") {
                Err(ParseError::CidrParseError(_)) => true,
                _ => false,
            },
            "Should be CidrParseError"
        );
    }

    #[test]
    fn test_contains() {
        assert!(IP::from_str("127.0.0.0/24")
            .unwrap()
            .contains(&IP::from_str("127.0.0.1").unwrap()));
        assert!(IP::from_str("127.0.0.0/24")
            .unwrap()
            .contains(&IP::from_str("127.0.0.50").unwrap()));
        assert!(IP::from_str("127.0.0.0/24")
            .unwrap()
            .contains(&IP::from_str("127.0.0.255").unwrap()));
        assert!(!IP::from_str("127.0.0.0/24")
            .unwrap()
            .contains(&IP::from_str("128.0.0.3").unwrap()));
    }
}
