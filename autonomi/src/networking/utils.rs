use crate::Multiaddr;
use libp2p::multiaddr::Protocol;

// @anselme: this is a duplicate function from ant_networking, wasn't sure where to place it

/// Verifies if `Multiaddr` contains IPv4 address that is not global.
/// This is used to filter out unroutable addresses from the Kademlia routing table.
pub(crate) fn multiaddr_is_global(multiaddr: &Multiaddr) -> bool {
    !multiaddr.iter().any(|addr| match addr {
        Protocol::Ip4(ip) => {
            // Based on the nightly `is_global` method (`Ipv4Addrs::is_global`), only using what is available in stable.
            // Missing `is_shared`, `is_benchmarking` and `is_reserved`.
            ip.is_unspecified()
                | ip.is_private()
                | ip.is_loopback()
                | ip.is_link_local()
                | ip.is_documentation()
                | ip.is_broadcast()
        }
        _ => false,
    })
}

/// Build a `Multiaddr` with the p2p protocol filtered out.
/// If it is a relayed address, then the relay's P2P address is preserved.
pub(crate) fn multiaddr_strip_p2p(multiaddr: &Multiaddr) -> Multiaddr {
    let is_relayed = multiaddr.iter().any(|p| matches!(p, Protocol::P2pCircuit));

    if is_relayed {
        // Do not add any PeerId after we've found the P2PCircuit protocol. The prior one is the relay's PeerId which
        // we should preserve.
        let mut before_relay_protocol = true;
        let mut new_multi_addr = Multiaddr::empty();
        for p in multiaddr.iter() {
            if matches!(p, Protocol::P2pCircuit) {
                before_relay_protocol = false;
            }
            if matches!(p, Protocol::P2p(_)) && !before_relay_protocol {
                continue;
            }
            new_multi_addr.push(p);
        }
        new_multi_addr
    } else {
        multiaddr
            .iter()
            .filter(|p| !matches!(p, Protocol::P2p(_)))
            .collect()
    }
}

pub(crate) fn is_a_relayed_peer<'a>(mut addrs: impl Iterator<Item = &'a Multiaddr>) -> bool {
    addrs.any(|multiaddr| multiaddr.iter().any(|p| matches!(p, Protocol::P2pCircuit)))
}
