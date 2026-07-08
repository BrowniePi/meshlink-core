"""Pure, transport-agnostic friendship state machine.

Shared identically by meshlink-app (Dart port, parity-tested) and
meshlink-node. No I/O, no storage, no clock: `transition` takes the current
record and an event and returns the new record plus side-effect descriptors
("emit FRIEND_ACCEPT", "issue capability token") for the caller to act on.

Friendship is mutual-consent and is the master switch for DMs and location.
`location_sharing_enabled` is a separate per-friend flag — being friends
never auto-shares location (mutual consent for friendship; unilateral opt-in
for sharing *your own* location to an existing friend). There is no event
that both creates a friendship and enables sharing without the local user
explicitly asking for both — never auto-accept, never auto-share.

States:  NONE → REQUESTED (outbound) / PENDING (inbound) → FRIENDS → REVOKED
"""
from dataclasses import dataclass, field, replace
from enum import Enum


class FriendshipState(Enum):
    NONE = "none"
    REQUESTED = "requested"   # we sent FRIEND_REQUEST, awaiting their consent
    PENDING = "pending"       # they sent FRIEND_REQUEST, awaiting our consent
    FRIENDS = "friends"
    REVOKED = "revoked"


class Event(Enum):
    # Local user actions:
    SEND_REQUEST = "send_request"
    ACCEPT = "accept"                      # accept the inbound request
    DECLINE = "decline"                    # decline the inbound request
    ENABLE_LOCATION = "enable_location"    # share my location with this friend
    DISABLE_LOCATION = "disable_location"
    UNFRIEND = "unfriend"
    # Inbound messages from the peer:
    RECV_REQUEST = "recv_request"          # FRIEND_REQUEST
    RECV_ACCEPT = "recv_accept"            # FRIEND_ACCEPT
    RECV_DECLINE = "recv_decline"          # FRIEND_DECLINE
    RECV_REVOKE = "recv_revoke"            # LOCATION_REVOKE (peer stopped sharing)


class Effect(Enum):
    """Side effects the caller must perform. The state machine only describes."""
    EMIT_FRIEND_REQUEST = "emit_friend_request"
    EMIT_FRIEND_ACCEPT = "emit_friend_accept"
    EMIT_FRIEND_DECLINE = "emit_friend_decline"
    ISSUE_CAPABILITY_TOKEN = "issue_capability_token"  # sign a grant to this peer
    EMIT_LOCATION_REVOKE = "emit_location_revoke"      # to the friend and to nodes
    PEER_STOPPED_SHARING = "peer_stopped_sharing"      # UI: their pin goes away


class InvalidTransition(Exception):
    def __init__(self, state: FriendshipState, event: Event) -> None:
        super().__init__(f"event {event.value} is illegal in state {state.value}")
        self.state = state
        self.event = event


@dataclass(frozen=True)
class FriendshipRecord:
    """Everything a friendship binds. Immutable — transitions return copies."""
    peer_username: str
    peer_curve25519_pub: bytes
    peer_ed25519_pub: bytes
    state: FriendshipState = FriendshipState.NONE
    location_sharing_enabled: bool = False           # *I* share with *them*
    capability_tokens_issued: tuple[bytes, ...] = field(default_factory=tuple)


def transition(
    record: FriendshipRecord, event: Event,
) -> tuple[FriendshipRecord, list[Effect]]:
    """Apply one event. Returns (new record, effects). Raises InvalidTransition
    for every edge not explicitly allowed — illegal transitions never pass
    silently, so a replayed or out-of-order message cannot corrupt consent."""
    state = record.state

    if event is Event.SEND_REQUEST and state is FriendshipState.NONE:
        return (replace(record, state=FriendshipState.REQUESTED),
                [Effect.EMIT_FRIEND_REQUEST])

    if event is Event.RECV_REQUEST and state is FriendshipState.NONE:
        return replace(record, state=FriendshipState.PENDING), []

    # Simultaneous cross-request: their request arrives while ours is in
    # flight. Consent stays explicit — the inbound request is surfaced and the
    # local user must still accept; nothing auto-accepts.
    if event is Event.RECV_REQUEST and state is FriendshipState.REQUESTED:
        return replace(record, state=FriendshipState.PENDING), []

    if event is Event.RECV_ACCEPT and state is FriendshipState.REQUESTED:
        return replace(record, state=FriendshipState.FRIENDS), []

    # FRIEND_ACCEPT while already friends is the token-refresh path: the peer
    # re-delivers a fresh capability token before the old one expires (or a
    # duplicate accept arrives via two relays). Idempotent — no state change,
    # no effects; the caller just stores the embedded token if present.
    if event is Event.RECV_ACCEPT and state is FriendshipState.FRIENDS:
        return record, []

    if event is Event.RECV_DECLINE and state is FriendshipState.REQUESTED:
        return replace(record, state=FriendshipState.NONE), []

    if event is Event.ACCEPT and state is FriendshipState.PENDING:
        return (replace(record, state=FriendshipState.FRIENDS),
                [Effect.EMIT_FRIEND_ACCEPT])

    if event is Event.DECLINE and state is FriendshipState.PENDING:
        return (replace(record, state=FriendshipState.NONE),
                [Effect.EMIT_FRIEND_DECLINE])

    if event is Event.ENABLE_LOCATION and state is FriendshipState.FRIENDS:
        return (replace(record, location_sharing_enabled=True),
                [Effect.ISSUE_CAPABILITY_TOKEN])

    if event is Event.DISABLE_LOCATION and state is FriendshipState.FRIENDS:
        if not record.location_sharing_enabled:
            return record, []
        return (replace(record, location_sharing_enabled=False,
                        capability_tokens_issued=()),
                [Effect.EMIT_LOCATION_REVOKE])

    if event is Event.RECV_REVOKE and state is FriendshipState.FRIENDS:
        # The *peer* stopped sharing with us; our own sharing flag is untouched.
        return record, [Effect.PEER_STOPPED_SHARING]

    if event is Event.UNFRIEND and state is FriendshipState.FRIENDS:
        effects = []
        if record.location_sharing_enabled:
            effects.append(Effect.EMIT_LOCATION_REVOKE)
        return (replace(record, state=FriendshipState.REVOKED,
                        location_sharing_enabled=False,
                        capability_tokens_issued=()),
                effects)

    raise InvalidTransition(state, event)


def record_issued_token(
    record: FriendshipRecord, token: bytes,
) -> FriendshipRecord:
    """Append a minted capability token (the caller performed
    ISSUE_CAPABILITY_TOKEN). Kept here so the record stays the single place
    that binds a friendship to its issued grants."""
    return replace(
        record,
        capability_tokens_issued=record.capability_tokens_issued + (token,),
    )
