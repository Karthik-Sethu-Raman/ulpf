import uuid
from ulpf_core.ids import raw_id_for, event_id_for

def test_raw_id_deterministic():
    assert raw_id_for("raw.logs", 3, 9182) == raw_id_for("raw.logs", 3, 9182)

def test_raw_id_varies_by_position():
    a, b, c = raw_id_for("raw.logs", 3, 1), raw_id_for("raw.logs", 4, 1), raw_id_for("raw.logs", 3, 2)
    assert len({a, b, c}) == 3

def test_event_id_versioned():
    r = uuid.UUID("00000000-0000-0000-0000-000000000001")
    assert event_id_for(r, 1) != event_id_for(r, 2)
    assert event_id_for(r, 1) == event_id_for(r, 1)
