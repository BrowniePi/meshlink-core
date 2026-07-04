from .message import Message


def check_attestation(msg: Message, sender_key: bytes) -> str | None:
    """Step 7: verify ticket-bound attestation token. Deliberate always-pass stub.

    The step's position in the pipeline (after signature verify, before
    route/deliver) is locked in now so Phase 5 only replaces this body, never
    restructures the pipeline. The signature already accepts what Phase 5
    needs: the message and the sender's public key.

    # TODO Phase 5: replace the always-pass return with real validation of a
    # JWT attestation token issued by meshlink-backend, asserting that
    # sender_key belongs to a ticket holder (checked against the node's local
    # attestation token cache). Drop reason on failure: no valid ticket-bound
    # identity token. A Sybil attacker must then buy one ticket per identity.
    """
    return None
