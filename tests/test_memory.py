from cyberai.memory import MemoryStore

def test_memory_round_trip(tmp_path):
    store = MemoryStore(tmp_path / "memory.db")
    store.remember("Windows Event Logs are useful", "study")
    result = store.search("Windows Event")
    assert len(result) == 1
    assert result[0]["category"] == "study"

def test_empty_memory_rejected(tmp_path):
    store = MemoryStore(tmp_path / "memory.db")
    try:
        store.remember("  ")
    except ValueError:
        pass
    else:
        raise AssertionError("Expected empty note to be rejected")
