"""A simulated mesh device: one SocketTransport + one RelayPipeline.

Relay-vs-deliver decision lives here, not in the pipeline — RelayPipeline.process()
only ever returns Outcome.DELIVER on success at Phase 0 (Outcome.RELAY is unused),
so the harness decides whether a delivered message is "for this device" (by zone_id)
and whether to spray it onward to neighbors.
"""
import time
from dataclasses import dataclass, field

from identity import DeviceIdentity, generate_keypair
from pipeline.pipeline import Outcome, RelayPipeline
from routing.spray_and_wait import split_copies
from sim.logging_util import log_event
from sim.packet import build_packet, rewrite_ttl_and_spray
from transport.socket_transport import SocketTransport

BROADCAST_ZONE = 0xFFFF


@dataclass
class Device:
    index: int
    zone_id: int
    identity: DeviceIdentity = field(default_factory=generate_keypair)
    transport: SocketTransport = field(default_factory=SocketTransport)
    pipeline: RelayPipeline = field(default_factory=RelayPipeline)
    neighbors: list[str] = field(default_factory=list)

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
            identity=self.identity,
            msg_id=msg_id,
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

        if msg.zone_id in (self.zone_id, BROADCAST_ZONE):
            log_event("delivered", self.index, msg_id=msg_id_hex, zone_id=msg.zone_id)

        copies = split_copies(msg.spray_l)
        if copies.forward > 0 and msg.ttl > 1:
            # ttl/spray_L are excluded from the signed region (see
            # pipeline.message.signed_region), so a relay only overwrites
            # those two bytes — it never re-signs, since it isn't the
            # original sender and doesn't hold that private key.
            new_raw = rewrite_ttl_and_spray(
                msg.raw, ttl=msg.ttl - 1, spray_l=copies.forward
            )
            for peer in self.neighbors:
                self.transport.send(peer, new_raw)
                log_event("relayed", self.index, msg_id=msg_id_hex, to=peer, ttl=msg.ttl - 1, spray_l=copies.forward)
