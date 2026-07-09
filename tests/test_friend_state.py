"""Friendship state machine: every legal edge, and every illegal one rejected."""
import itertools

import pytest

from friends.state import (
    Effect,
    Event,
    FriendshipRecord,
    FriendshipState,
    InvalidTransition,
    record_issued_token,
    transition,
)


def make_record(state=FriendshipState.NONE, **kwargs):
    return FriendshipRecord(
        peer_username="ada",
        peer_curve25519_pub=b"\x01" * 32,
        peer_ed25519_pub=b"\x02" * 32,
        state=state,
        **kwargs,
    )


# (start state, extra record kwargs, event, end state, expected effects)
LEGAL_EDGES = [
    (FriendshipState.NONE, {}, Event.SEND_REQUEST,
     FriendshipState.REQUESTED, [Effect.EMIT_FRIEND_REQUEST]),
    (FriendshipState.NONE, {}, Event.RECV_REQUEST,
     FriendshipState.PENDING, []),
    (FriendshipState.REQUESTED, {}, Event.RECV_REQUEST,
     FriendshipState.PENDING, []),  # simultaneous cross-request
    (FriendshipState.REQUESTED, {}, Event.RECV_ACCEPT,
     FriendshipState.FRIENDS, []),
    (FriendshipState.FRIENDS, {}, Event.RECV_ACCEPT,
     FriendshipState.FRIENDS, []),  # token refresh / duplicate accept
    (FriendshipState.REQUESTED, {}, Event.RECV_DECLINE,
     FriendshipState.NONE, []),
    (FriendshipState.PENDING, {}, Event.ACCEPT,
     FriendshipState.FRIENDS, [Effect.EMIT_FRIEND_ACCEPT]),
    (FriendshipState.PENDING, {}, Event.DECLINE,
     FriendshipState.NONE, [Effect.EMIT_FRIEND_DECLINE]),
    (FriendshipState.FRIENDS, {}, Event.ENABLE_LOCATION,
     FriendshipState.FRIENDS, [Effect.ISSUE_CAPABILITY_TOKEN]),
    (FriendshipState.FRIENDS, {"location_sharing_enabled": True},
     Event.DISABLE_LOCATION, FriendshipState.FRIENDS,
     [Effect.EMIT_LOCATION_REVOKE]),
    (FriendshipState.FRIENDS, {}, Event.DISABLE_LOCATION,
     FriendshipState.FRIENDS, []),  # idempotent when not sharing
    (FriendshipState.FRIENDS, {}, Event.RECV_REVOKE,
     FriendshipState.FRIENDS, [Effect.PEER_STOPPED_SHARING]),
    (FriendshipState.FRIENDS, {}, Event.UNFRIEND,
     FriendshipState.REVOKED, []),
    (FriendshipState.FRIENDS, {"location_sharing_enabled": True},
     Event.UNFRIEND, FriendshipState.REVOKED, [Effect.EMIT_LOCATION_REVOKE]),
]


@pytest.mark.parametrize(
    "start,extra,event,end,effects", LEGAL_EDGES,
    ids=[f"{s.value}--{e.value}" + ("+" + ",".join(k for k in x) if x else "")
         for s, x, e, _, _ in LEGAL_EDGES],
)
def test_legal_edge(start, extra, event, end, effects):
    record, got = transition(make_record(start, **extra), event)
    assert record.state is end
    assert got == effects


def test_every_other_edge_is_illegal():
    """Exhaustive complement of LEGAL_EDGES: no (state, event) pair outside the
    table may pass — an out-of-order or replayed message must never move
    consent state silently."""
    legal = {(s, e) for s, _, e, _, _ in LEGAL_EDGES}
    for state, event in itertools.product(FriendshipState, Event):
        if (state, event) in legal:
            continue
        with pytest.raises(InvalidTransition):
            transition(make_record(state), event)


def test_friendship_never_auto_shares_location():
    """Becoming friends must not flip location_sharing_enabled (mutual consent
    for friendship; separate unilateral opt-in for location)."""
    record, _ = transition(make_record(FriendshipState.PENDING), Event.ACCEPT)
    assert record.state is FriendshipState.FRIENDS
    assert record.location_sharing_enabled is False

    record, _ = transition(make_record(FriendshipState.REQUESTED), Event.RECV_ACCEPT)
    assert record.location_sharing_enabled is False


def test_disable_location_clears_issued_tokens():
    record = make_record(FriendshipState.FRIENDS, location_sharing_enabled=True)
    record = record_issued_token(record, b"\x03" * 98)
    assert record.capability_tokens_issued == (b"\x03" * 98,)
    record, effects = transition(record, Event.DISABLE_LOCATION)
    assert effects == [Effect.EMIT_LOCATION_REVOKE]
    assert record.capability_tokens_issued == ()
    assert record.location_sharing_enabled is False


def test_unfriend_while_sharing_revokes_and_clears():
    record = make_record(FriendshipState.FRIENDS, location_sharing_enabled=True)
    record = record_issued_token(record, b"\x03" * 98)
    record, effects = transition(record, Event.UNFRIEND)
    assert record.state is FriendshipState.REVOKED
    assert effects == [Effect.EMIT_LOCATION_REVOKE]
    assert record.location_sharing_enabled is False
    assert record.capability_tokens_issued == ()


def test_records_are_immutable():
    record = make_record()
    with pytest.raises(Exception):
        record.state = FriendshipState.FRIENDS
