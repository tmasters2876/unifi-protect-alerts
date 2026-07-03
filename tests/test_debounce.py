import debounce


def test_debounce_blocks_within_window(monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr(debounce.time, "time", lambda: clock["t"])

    d = debounce.Debouncer()
    assert d.is_debounced(("weapon", "cam1"), 10) is False  # first call always passes
    assert d.is_debounced(("weapon", "cam1"), 10) is True  # immediate repeat is blocked


def test_debounce_allows_after_window_elapses(monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr(debounce.time, "time", lambda: clock["t"])

    d = debounce.Debouncer()
    assert d.is_debounced(("weapon", "cam1"), 10) is False
    clock["t"] += 11
    assert d.is_debounced(("weapon", "cam1"), 10) is False


def test_debounce_keys_are_independent(monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr(debounce.time, "time", lambda: clock["t"])

    d = debounce.Debouncer()
    assert d.is_debounced(("weapon", "cam1"), 10) is False
    assert d.is_debounced(("weapon", "cam2"), 10) is False  # different camera, independent window
    assert d.is_debounced(("raccoon", "cam1"), 10) is False  # different event type, independent window
