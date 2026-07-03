from payload import (
    absolute_url,
    data_url_to_bytes,
    extract_camera_id_from_urls,
    extract_smart_types,
    find_camera_id,
    find_camera_name_in_payload,
    find_timestamp_ms,
    pick_image_source,
)


def test_find_camera_id_from_trigger(data_url_payload):
    assert find_camera_id(data_url_payload) == "abcdef0123456789abcdef01"


def test_find_camera_name_in_payload(data_url_payload):
    assert find_camera_name_in_payload(data_url_payload) == "Front Door"


def test_find_camera_name_missing(thumbnail_url_payload):
    assert find_camera_name_in_payload(thumbnail_url_payload) is None


def test_find_timestamp_ms(data_url_payload):
    assert find_timestamp_ms(data_url_payload) == 1735689600000


def test_find_timestamp_ms_fallback_to_now():
    ts = find_timestamp_ms({})
    assert isinstance(ts, int) and ts > 1_000_000_000_000


def test_extract_smart_types(data_url_payload, thumbnail_url_payload):
    assert extract_smart_types(data_url_payload) == {"person", "animal"}
    assert extract_smart_types(thumbnail_url_payload) == {"vehicle"}


def test_pick_image_source_data_url(data_url_payload):
    kind, val = pick_image_source(data_url_payload)
    assert kind == "data"
    assert val.startswith("data:image/jpeg;base64,")


def test_pick_image_source_thumbnail_url(thumbnail_url_payload):
    kind, val = pick_image_source(thumbnail_url_payload)
    assert kind == "url"
    assert "thumbnailUrl" not in val  # value itself, not the key
    assert val.startswith("https://")


def test_extract_camera_id_from_urls(thumbnail_url_payload):
    assert extract_camera_id_from_urls(thumbnail_url_payload) == "abcdef0123456789abcdef01"


def test_data_url_to_bytes_roundtrip():
    assert data_url_to_bytes("data:image/jpeg;base64,Zm9vYmFy") == b"foobar"


def test_data_url_to_bytes_invalid_returns_empty():
    assert data_url_to_bytes("not-a-data-url") == b""


def test_absolute_url_passthrough_for_full_urls():
    assert absolute_url("https://example.com/x.jpg") == "https://example.com/x.jpg"


def test_absolute_url_empty_for_junk():
    assert absolute_url(None) == ""
    assert absolute_url("") == ""
