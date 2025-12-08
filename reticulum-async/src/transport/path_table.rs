use std::{collections::HashMap, time::Instant};

use reticulum_core::{
    hash::{AddressHash, Hash},
    packet::{DestinationType, Header, HeaderType, IfacFlag, Packet, PacketType, PropagationType},
};

pub struct PathEntry {
    pub timestamp: Instant,
    pub received_from: AddressHash,
    pub hops: u8,
    pub iface: AddressHash,
    pub packet_hash: Hash,
}

pub struct PathTable {
    map: HashMap<AddressHash, PathEntry>,
}

impl PathTable {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn get(&self, destination: &AddressHash) -> Option<&PathEntry> {
        self.map.get(destination)
    }

    pub fn next_hop_full(&self, destination: &AddressHash) -> Option<(AddressHash, AddressHash)> {
        self.map
            .get(destination)
            .map(|entry| (entry.received_from, entry.iface))
    }

    pub fn next_hop_iface(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.map.get(destination).map(|entry| entry.iface)
    }

    pub fn next_hop(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.map.get(destination).map(|entry| entry.received_from)
    }

    pub fn handle_announce(
        &mut self,
        announce: &Packet,
        transport_id: Option<AddressHash>,
        iface: AddressHash,
    ) {
        let hops = announce.header.hops + 1;

        if let Some(existing_entry) = self.map.get(&announce.destination) {
            if hops >= existing_entry.hops {
                return;
            }
        }

        let received_from = transport_id.unwrap_or(announce.destination);
        let new_entry = PathEntry {
            timestamp: Instant::now(),
            received_from,
            hops,
            iface,
            packet_hash: announce.hash(),
        };

        self.map.insert(announce.destination, new_entry);

        log::info!(
            "{} is now reachable over {} hops through {}",
            announce.destination,
            hops,
            received_from,
        );
    }

    pub fn handle_inbound_packet(
        &self,
        original_packet: &Packet,
        lookup: Option<AddressHash>,
    ) -> (Packet, Option<AddressHash>) {
        let lookup = lookup.unwrap_or(original_packet.destination);

        let entry = match self.map.get(&lookup) {
            Some(entry) => entry,
            None => return (*original_packet, None),
        };

        // Calculate remaining hops to destination
        // entry.hops = total hops from announce
        // original_packet.header.hops = hops already taken
        // +1 = the hop we're about to take
        let remaining_hops = entry.hops.saturating_sub(original_packet.header.hops + 1);

        log::debug!(
            "handle_inbound_packet: dst={} total_hops={} taken={} remaining={}",
            original_packet.destination,
            entry.hops,
            original_packet.header.hops,
            remaining_hops
        );

        // Determine packet format based on remaining hops
        // This matches Python RNS/Transport.py:1343-1354
        let (header_type, propagation_type, transport) = if remaining_hops > 1 {
            // Multi-hop: keep transport header with next hop
            log::trace!("Multi-hop routing: keeping Type2/Transport header");
            (
                HeaderType::Type2,
                PropagationType::Transport,
                Some(entry.received_from),
            )
        } else if remaining_hops == 1 {
            // Final hop: STRIP transport header (Python does this at line 1350-1354)
            log::debug!("Final hop: stripping transport header to Type1/Broadcast");
            (HeaderType::Type1, PropagationType::Broadcast, None)
        } else {
            // Destination is directly reachable (0 hops remaining)
            log::trace!("Direct delivery: no transport header needed");
            (HeaderType::Type1, PropagationType::Broadcast, None)
        };

        (
            Packet {
                header: Header {
                    ifac_flag: original_packet.header.ifac_flag, // Preserve original IFAC flag
                    header_type,
                    propagation_type,
                    destination_type: original_packet.header.destination_type,
                    packet_type: original_packet.header.packet_type,
                    hops: original_packet.header.hops + 1,
                },
                ifac: original_packet.ifac, // Preserve original IFAC if present
                destination: original_packet.destination,
                transport,
                context: original_packet.context,
                data: original_packet.data,
            },
            Some(entry.iface),
        )
    }

    pub fn refresh(&mut self, destination: &AddressHash) {
        if let Some(entry) = self.map.get_mut(destination) {
            entry.timestamp = Instant::now();
        }
    }

    pub fn handle_packet(&mut self, original_packet: &Packet) -> (Packet, Option<AddressHash>) {
        if original_packet.header.header_type == HeaderType::Type2 {
            return (*original_packet, None);
        }

        if original_packet.header.packet_type == PacketType::Announce {
            return (*original_packet, None);
        }

        if original_packet.header.destination_type == DestinationType::Plain
            || original_packet.header.destination_type == DestinationType::Group
        {
            return (*original_packet, None);
        }

        let entry = match self.map.get(&original_packet.destination) {
            Some(entry) => entry,
            None => return (*original_packet, None),
        };

        // For local destinations (1 hop), keep original propagation and no transport_id
        // For multi-hop destinations (2+ hops), use Transport propagation with transport_id
        let is_multihop = entry.hops > 1;

        (
            Packet {
                header: Header {
                    ifac_flag: original_packet.header.ifac_flag, // Always preserve original IFAC flag
                    header_type: if is_multihop {
                        HeaderType::Type2
                    } else {
                        original_packet.header.header_type
                    },
                    propagation_type: if is_multihop {
                        PropagationType::Transport
                    } else {
                        original_packet.header.propagation_type
                    },
                    destination_type: original_packet.header.destination_type,
                    packet_type: original_packet.header.packet_type,
                    hops: original_packet.header.hops,
                },
                ifac: original_packet.ifac, // Always preserve original IFAC if present
                destination: original_packet.destination,
                transport: if is_multihop {
                    Some(entry.received_from)
                } else {
                    None
                },
                context: original_packet.context,
                data: original_packet.data,
            },
            Some(entry.iface),
        )
    }
}
