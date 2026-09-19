import uuid

# Fixed forever — changing it invalidates every stored raw_id/event_id.
NAMESPACE = uuid.UUID("7308095f-9773-5212-acef-a4c9f422b66c")

def raw_id_for(topic: str, partition: int, offset: int) -> uuid.UUID:
    """Stable across replays: the same message always maps to the same id."""
    return uuid.uuid5(NAMESPACE, f"{topic}:{partition}:{offset}")

def event_id_for(raw_id: uuid.UUID, rule_version: int) -> uuid.UUID:
    """Re-parse under a new version mints a new id; replay of the same
    version collides and is skipped (idempotent append, spec §4)."""
    return uuid.uuid5(NAMESPACE, f"{raw_id}:{rule_version}")
