"""A simulated mesh device: one SocketTransport + one RelayPipeline.

Relay-vs-deliver decision lives here, not in the pipeline — RelayPipeline.process()
only ever returns Outcome.DELIVER on success at Phase 0 (Outcome.RELAY is unused),
so the harness decides whether a delivered message is "for this device" (by zone_id)
and whether to spray it onward to neighbors.
"""
import os
import time
from dataclasses import dataclass, field

from pipeline.message import Message
from pipeline.pipeline import Outcome, RelayPipeline
from routing.spray_and_wait import split_copies
from sim.logging_util import log_event
from sim.packet import build_packet
from transport.socket_transport import SocketTransport

BROADCAST_ZONE = 0xFFFF

# msg_type values from docs/message-format.md §ACK
MSG_TYPE_ACK = 0x03
MSG_TYPE_ACK_SUPPRESS = 0x04
ACK_TTL = 3  # matches the worked example in docs/message-format.md


@dataclass
class Device:
    index: int
    zone_id: int
    transport: SocketTransport = field(default_factory=SocketTransport)
    pipeline: RelayPipeline = field(default_factory=RelayPipeline)
    neighbors: list[str] = field(default_factory=list)
    _acked: set[bytes] = field(default_factory=set)

    def start(self) -> None:
        self.transport.start()
        self.transport.on_receive(self._on_receive)

    @property
    def address(self) -> str:
        return self.transport.address

    def connect_to(self, peer_address: str) -> None:
        self.transport.connect_peer(peer_address)

    def inject(
        self,
        *,
        payload: bytes,
        ttl: int,
        spray_l: int,
        zone_id: int,
        msg_id: bytes,
    ) -> None:
        raw = build_packet(
            msg_id=msg_id,
            sender_key=b"\x01" * 32,
            ephem_id=b"\x02" * 16,
            timestamp=int(time.time()),
            ttl=ttl,
            spray_l=spray_l,
            zone_id=zone_id,
            msg_type=1,
            payload=payload,
        )
        log_event("injected", self.index, msg_id=msg_id.hex()[:8], zone_id=zone_id, ttl=ttl, spray_l=spray_l)
        self._handle_local(raw)

    def _on_receive(self, sender_peer_id: str, raw: bytes) -> None:
        log_event("received", self.index, **{"from": sender_peer_id})
        self._handle_local(raw)

    def _handle_local(self, raw: bytes) -> None:
        result = self.pipeline.process(raw)

        if result.outcome == Outcome.DROP:
            log_event("dropped", self.index, reason=result.drop_reason)
            return

        msg = result.message
        msg_id_hex = msg.msg_id.hex()[:8]

        if msg.msg_type in (MSG_TYPE_ACK, MSG_TYPE_ACK_SUPPRESS):
            self._handle_ack(msg)
            return

        if msg.zone_id in (self.zone_id, BROADCAST_ZONE):
            log_event("delivered", self.index, msg_id=msg_id_hex, zone_id=msg.zone_id)
            if msg.msg_id not in self._acked:
                self._send_ack(msg)

        if msg.msg_id in self._acked:
            log_event("suppressed", self.index, msg_id=msg_id_hex, ttl=msg.ttl, spray_l=msg.spray_l, reason="ack received")
            return

        copies = split_copies(msg.spray_l)
        if copies.forward > 0 and msg.ttl > 1:
            new_raw = build_packet(
                msg_id=msg.msg_id,
                sender_key=msg.sender_key,
                ephem_id=msg.ephem_id,
                timestamp=msg.timestamp,
                ttl=msg.ttl - 1,
                spray_l=copies.forward,
                zone_id=msg.zone_id,
                msg_type=msg.msg_type,
                payload=msg.payload,
                signature=msg.signature,
            )
            for peer in self.neighbors:
                self.transport.send(peer, new_raw)
                log_event("relayed", self.index, msg_id=msg_id_hex, to=peer, ttl=msg.ttl - 1, spray_l=copies.forward)

    def _send_ack(self, msg: Message) -> None:
        """Delivery acknowledgement (msg_type ACK): floods back to neighbors
        and marks msg.msg_id as acked so this device suppresses its own
        further spray of it (docs/message-format.md §ACK)."""
        self._acked.add(msg.msg_id)
        ack_raw = build_packet(
            msg_id=os.urandom(16),
            sender_key=msg.sender_key,
            ephem_id=msg.ephem_id,
            timestamp=int(time.time()),
            ttl=ACK_TTL,
            spray_l=1,
            zone_id=BROADCAST_ZONE,
            msg_type=MSG_TYPE_ACK,
            payload=msg.msg_id,
        )
        for peer in self.neighbors:
            self.transport.send(peer, ack_raw)
            log_event("ack_sent", self.index, acked_msg_id=msg.msg_id.hex()[:8], to=peer)

    def _handle_ack(self, msg: Message) -> None:
        """Step on receiving an ACK or ACK_SUPPRESS: remember the acked
        msg_id (so a still-pending spray copy of it gets suppressed) and
        relay onward as ACK_SUPPRESS while ttl budget remains."""
        acked_msg_id = msg.payload[:16]
        self._acked.add(acked_msg_id)
        log_event("ack_received", self.index, acked_msg_id=acked_msg_id.hex()[:8], ttl=msg.ttl)

        if msg.ttl <= 1:
            return

        suppress_raw = build_packet(
            msg_id=msg.msg_id,
            sender_key=msg.sender_key,
            ephem_id=msg.ephem_id,
            timestamp=msg.timestamp,
            ttl=msg.ttl - 1,
            spray_l=1,
            zone_id=msg.zone_id,
            msg_type=MSG_TYPE_ACK_SUPPRESS,
            payload=msg.payload,
            signature=msg.signature,
        )
        for peer in self.neighbors:
            self.transport.send(peer, suppress_raw)
            log_event("ack_relayed", self.index, acked_msg_id=acked_msg_id.hex()[:8], to=peer, ttl=msg.ttl - 1)
