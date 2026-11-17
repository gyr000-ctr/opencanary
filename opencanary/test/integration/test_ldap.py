"""Integration tests for the LDAP honeypot using raw BER over TCP sockets.

No LDAP client library is available in the test environment, so frames are
hand built with the module's own BER encoder and sent over plain sockets.
"""

import socket

from opencanary.logger import LoggerBase
from opencanary.modules.ldap import (
    TAG_BOOLEAN,
    TAG_ENUMERATED,
    BERDecoder,
    encode_integer,
    encode_octet_string,
    encode_sequence,
    encode_tlv,
)


def tlv(tag, value):
    return encode_tlv(tag, value)


def bind_request(message_id, version=3, name=b"", password=b"", auth_tag=0x80):
    body = (
        encode_integer(version)
        + encode_octet_string(name)
        + tlv(auth_tag, password)
    )
    return encode_sequence(encode_integer(message_id) + tlv(0x60, body))


def search_request(
    message_id,
    base=b"dc=example,dc=com",
    scope=2,
    filter_bytes=None,
    attributes=None,
):
    if filter_bytes is None:
        filter_bytes = tlv(
            0xA3, encode_octet_string("cn") + encode_octet_string("admin")
        )
    if attributes is None:
        attributes = encode_sequence(b"")
    body = (
        encode_octet_string(base)
        + encode_integer(scope, TAG_ENUMERATED)
        + encode_integer(0, TAG_ENUMERATED)
        + encode_integer(0)
        + encode_integer(0)
        + tlv(TAG_BOOLEAN, b"\x00")
        + filter_bytes
        + attributes
    )
    return encode_sequence(encode_integer(message_id) + tlv(0x63, body))


def unbind_request(message_id):
    return encode_sequence(encode_integer(message_id) + tlv(0x42, b""))


def open_socket(service):
    sock = socket.create_connection(
        (service.host, service.port), timeout=5
    )
    return sock


def recv_frames(sock, count):
    """Read exactly count complete LDAPMessage frames from the socket."""
    data = b""
    frames = []
    while len(frames) < count:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        while True:
            frame, data = _split_one_frame(data)
            if frame is None:
                break
            frames.append(frame)
    return frames, data


def _split_one_frame(data):
    if len(data) < 2:
        return None, data
    if data[0] != 0x30:
        raise ValueError("expected SEQUENCE envelope, got 0x%02x" % data[0])
    first = data[1]
    if first < 0x80:
        header_len, length = 2, first
    else:
        num_bytes = first & 0x7F
        if len(data) < 2 + num_bytes:
            return None, data
        header_len = 2 + num_bytes
        length = 0
        for byte in data[2:header_len]:
            length = (length << 8) | byte
    if len(data) < header_len + length:
        return None, data
    return data[: header_len + length], data[header_len + length :]


def frame_summary(frame):
    """Return (message_id, application_tag, result_code_or_none)."""
    envelope = BERDecoder(frame, 2**20).read_sequence()
    message_id = envelope.read_integer()
    tag, value, _ = envelope.read_tlv()
    app_tag = tag & 0x1F
    if app_tag == 4:
        return message_id, app_tag, None
    inner = BERDecoder(value, 2**20)
    return message_id, app_tag, inner.read_integer(TAG_ENUMERATED)


def get_ldap_log(service, start, event):
    return service.get_matching_log(
        start,
        lambda e: e.get("logtype") == LoggerBase.LOG_LDAP_REQUEST
        and e.get("dst_port") == service.port
        and e.get("logdata", {}).get("EVENT") == event,
    )


def test_anonymous_bind_succeeds(canary):
    service = canary("ldap")
    start = service.get_log_count()
    with open_socket(service) as sock:
        sock.sendall(bind_request(1))
        frames, _ = recv_frames(sock, 1)

    assert frame_summary(frames[0]) == (1, 1, 0)  # bindResponse success
    log = get_ldap_log(service, start, "BIND")
    assert log["logdata"]["ANONYMOUS"] is True
    assert log["logdata"]["RESULT"] == 0


def test_simple_bind_failure_logs_dn_and_password(canary):
    service = canary("ldap")
    start = service.get_log_count()
    dn = b"cn=admin,dc=example,dc=com"
    with open_socket(service) as sock:
        sock.sendall(bind_request(1, name=dn, password=b"ldap_honeycred_test"))
        frames, _ = recv_frames(sock, 1)

    assert frame_summary(frames[0]) == (1, 1, 49)  # invalidCredentials
    log = get_ldap_log(service, start, "BIND")
    assert log["logdata"]["DN"] == dn.decode()
    assert log["logdata"]["USERNAME"] == dn.decode()
    assert log["logdata"]["PASSWORD"] == "ldap_honeycred_test"
    assert log["honeycred"] is True


def test_empty_password_bind_is_rejected(canary):
    service = canary("ldap")
    start = service.get_log_count()
    with open_socket(service) as sock:
        sock.sendall(bind_request(1, name=b"cn=svc,dc=example,dc=com"))
        frames, _ = recv_frames(sock, 1)

    assert frame_summary(frames[0]) == (1, 1, 49)
    log = get_ldap_log(service, start, "BIND")
    assert log["logdata"]["PASSWORD"] == ""
    assert log["logdata"]["ANONYMOUS"] is False


def test_search_returns_forged_entries_and_logs(canary):
    service = canary("ldap")
    start = service.get_log_count()
    equality = tlv(
        0xA3, encode_octet_string("uid") + encode_octet_string("admin")
    )
    with open_socket(service) as sock:
        sock.sendall(bind_request(1))
        recv_frames(sock, 1)
        sock.sendall(
            search_request(
                2,
                filter_bytes=equality,
                attributes=encode_sequence(encode_octet_string("cn")),
            )
        )
        # One entry plus the resultDone frame.
        frames, _ = recv_frames(sock, 2)

    summaries = [frame_summary(frame) for frame in frames]
    assert (2, 4, None) in summaries
    assert summaries[-1] == (2, 5, 0)
    log = get_ldap_log(service, start, "SEARCH")
    assert log["logdata"]["FILTER"] == "(uid=admin)"
    assert log["logdata"]["ATTRIBUTES"] == ["cn"]
    assert log["logdata"]["SCOPE"] == 2
    assert log["logdata"]["BASE_OBJECT"] == "dc=example,dc=com"


def test_base_object_scope_returns_exactly_one_entry(canary):
    service = canary("ldap")
    with open_socket(service) as sock:
        sock.sendall(bind_request(1))
        recv_frames(sock, 1)
        sock.sendall(
            search_request(2, base=b"dc=example,dc=com", scope=0)
        )
        frames, _ = recv_frames(sock, 2)

    entries = [frame for frame in frames if frame_summary(frame)[1] == 4]
    assert len(entries) == 1


def test_fragmented_bind_is_processed_after_all_bytes(canary):
    service = canary("ldap")
    start = service.get_log_count()
    request = bind_request(1, name=b"cn=admin", password=b"pw")
    with open_socket(service) as sock:
        sock.sendall(request[:2])
        sock.sendall(request[2:7])
        sock.sendall(request[7:])
        frames, _ = recv_frames(sock, 1)

    assert frame_summary(frames[0]) == (1, 1, 49)
    get_ldap_log(service, start, "BIND")


def test_multiple_requests_on_one_connection(canary):
    service = canary("ldap")
    with open_socket(service) as sock:
        sock.sendall(bind_request(1) + search_request(2) + search_request(3))
        # bind response, then entry + resultDone for each of two searches.
        frames, _ = recv_frames(sock, 5)

    summaries = [frame_summary(frame) for frame in frames]
    message_ids = [summary[0] for summary in summaries]
    assert message_ids == sorted(message_ids)
    assert {1, 2, 3} <= set(message_ids)


def test_unbind_closes_connection(canary):
    service = canary("ldap")
    with open_socket(service) as sock:
        sock.sendall(bind_request(1))
        recv_frames(sock, 1)
        sock.sendall(unbind_request(2))
        # Server closes the TCP connection without an unbind response.
        assert sock.recv(4096) == b""


def test_malformed_outer_tag_gets_protocol_error_and_close(canary):
    service = canary("ldap")
    start = service.get_log_count()
    with open_socket(service) as sock:
        sock.sendall(b"\x02\x01\x01")
        frames, _ = recv_frames(sock, 1)
        # Server then drops the connection.
        assert sock.recv(4096) == b""

    # Unsolicited Notice of Disconnection, message id 0, protocolError.
    assert frame_summary(frames[0]) == (0, 24, 2)
    log = get_ldap_log(service, start, "ERROR")
    assert log["logdata"]["ERROR"]


def test_illegal_operation_code_gets_protocol_error_and_close(canary):
    service = canary("ldap")
    start = service.get_log_count()
    bad = encode_sequence(encode_integer(1) + tlv(0x60 + 99, b""))
    with open_socket(service) as sock:
        sock.sendall(bad)
        frames, _ = recv_frames(sock, 1)
        assert sock.recv(4096) == b""

    assert frame_summary(frames[0]) == (0, 24, 2)
    get_ldap_log(service, start, "ERROR")


def test_indefinite_length_is_rejected(canary):
    service = canary("ldap")
    start = service.get_log_count()
    with open_socket(service) as sock:
        sock.sendall(b"\x30\x80\x02\x01\x01\x00\x00")
        frames, _ = recv_frames(sock, 1)
        assert sock.recv(4096) == b""

    assert frame_summary(frames[0]) == (0, 24, 2)
    get_ldap_log(service, start, "ERROR")
