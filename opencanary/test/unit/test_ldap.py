from unittest.mock import Mock

import pytest
from twisted.internet.task import Clock
from twisted.internet.testing import StringTransport

from opencanary.logger import LoggerBase
from opencanary.modules.ldap import (
    TAG_BOOLEAN,
    TAG_ENUMERATED,
    TAG_INTEGER,
    BERDecoder,
    CanaryLDAP,
    LDAPProtocolError,
    encode_integer,
    encode_octet_string,
    encode_sequence,
    encode_tlv,
)

LDAP_LOG_TYPE = LoggerBase.LOG_LDAP_REQUEST


def tlv(tag, value):
    return encode_tlv(tag, value)


def bind_request(message_id, version=3, name=b"", password=None, auth_tag=0x80):
    if password is None:
        password = b""
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
    size_limit=0,
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
        + encode_integer(size_limit)
        + encode_integer(0)
        + tlv(TAG_BOOLEAN, b"\x00")
        + filter_bytes
        + attributes
    )
    return encode_sequence(encode_integer(message_id) + tlv(0x63, body))


def unbind_request(message_id=2):
    return encode_sequence(encode_integer(message_id) + tlv(0x42, b""))


def parse_messages(data):
    """Walk LDAPMessage frames, returning (message_id, app_tag, result_code)."""
    messages = []
    decoder = BERDecoder(data, 2**20)
    while not decoder.at_end():
        envelope = decoder.read_sequence()
        message_id = envelope.read_integer()
        tag, value, _ = envelope.read_tlv()
        app_tag = tag & 0x1F
        if app_tag == 4:
            # SearchResultEntry has no result code.
            messages.append((message_id, app_tag, None))
            continue
        inner = BERDecoder(value, 2**20)
        result_code = inner.read_integer(TAG_ENUMERATED)
        messages.append((message_id, app_tag, result_code))
    return messages


@pytest.fixture
def ldap_factory():
    protocols = []

    def build(**settings):
        config = Mock()
        config.getVal.side_effect = lambda key, default=None: settings.get(key, default)
        logger = Mock(spec=["log", "LOG_LDAP_REQUEST"])
        logger.LOG_LDAP_REQUEST = LDAP_LOG_TYPE
        factory = CanaryLDAP(config=config, logger=logger)
        factory.reactor = Clock()

        def connect():
            protocol = factory.buildProtocol(None)
            protocol.makeConnection(StringTransport())
            protocols.append(protocol)
            return protocol

        return factory, connect

    yield build

    for protocol in protocols:
        if protocol.connected:
            protocol.connectionLost(None)


def logged_events(protocol):
    return [
        call.args[0]
        for call in protocol.factory.logger.log.call_args_list
    ]


# ---------------------------------------------------------------------------
# Bind behaviour
# ---------------------------------------------------------------------------


def test_anonymous_bind_succeeds_and_logs(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    protocol.dataReceived(bind_request(1, name=b"", password=b""))

    messages = parse_messages(protocol.transport.value())
    assert messages == [(1, 1, 0)]  # bindResponse, success
    assert not protocol.transport.disconnecting

    event = logged_events(protocol)[0]
    assert event["logtype"] == LDAP_LOG_TYPE
    assert event["logdata"]["EVENT"] == "BIND"
    assert event["logdata"]["ANONYMOUS"] is True
    assert event["logdata"]["RESULT"] == 0
    assert event["logdata"]["DN"] == ""
    protocol.setTimeout(None)


def test_simple_bind_failure_captures_dn_and_password(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    dn = b"cn=admin,dc=example,dc=com"
    protocol.dataReceived(bind_request(1, name=dn, password=b"s3cret"))

    messages = parse_messages(protocol.transport.value())
    assert messages == [(1, 1, 49)]  # invalidCredentials

    event = logged_events(protocol)[0]
    assert event["logdata"]["EVENT"] == "BIND"
    assert event["logdata"]["DN"] == dn.decode()
    assert event["logdata"]["USERNAME"] == dn.decode()
    assert event["logdata"]["PASSWORD"] == "s3cret"
    assert event["logdata"]["ANONYMOUS"] is False
    assert event["logdata"]["RESULT"] == 49
    protocol.setTimeout(None)


def test_empty_password_bind_is_invalid_credentials(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    protocol.dataReceived(bind_request(1, name=b"cn=admin,dc=example,dc=com"))

    messages = parse_messages(protocol.transport.value())
    assert messages == [(1, 1, 49)]
    event = logged_events(protocol)[0]
    assert event["logdata"]["PASSWORD"] == ""
    assert event["logdata"]["ANONYMOUS"] is False
    protocol.setTimeout(None)


def test_sasl_bind_is_rejected_but_connection_lives(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    sasl = encode_sequence(encode_octet_string("DIGEST-MD5"))
    protocol.dataReceived(bind_request(1, name=b"cn=x", auth_tag=0xA3, password=sasl))

    messages = parse_messages(protocol.transport.value())
    assert messages == [(1, 1, 7)]  # authMethodNotSupported
    assert not protocol.transport.disconnecting
    protocol.setTimeout(None)


def test_honeycred_hook_marks_configured_credentials(ldap_factory):
    factory, connect = ldap_factory(
        **{
            "ldap.honeycreds": [
                {"username": "cn=admin,dc=example,dc=com", "password": "s3cret"}
            ]
        }
    )
    assert factory.honeyCredHook is not None
    protocol = connect()
    protocol.dataReceived(
        bind_request(
            1, name=b"cn=admin,dc=example,dc=com", password=b"s3cret"
        )
    )
    event = logged_events(protocol)[0]
    assert event["honeycred"] is True
    protocol.setTimeout(None)


# ---------------------------------------------------------------------------
# Search behaviour and scope semantics
# ---------------------------------------------------------------------------


def test_search_returns_entries_and_logs_filter(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    protocol.dataReceived(bind_request(1))
    protocol.dataReceived(
        search_request(
            2,
            filter_bytes=tlv(
                0xA3,
                encode_octet_string("uid") + encode_octet_string("admin"),
            ),
            attributes=encode_sequence(encode_octet_string("cn")),
        )
    )

    raw = protocol.transport.value()
    frames = parse_messages(raw)
    # At least one searchResultEntry (tag 4) then resultDone (tag 5, success)
    search_frames = [frame for frame in frames if frame[0] == 2]
    assert search_frames[-1] == (2, 5, 0)
    assert any(frame[1] == 4 for frame in search_frames)

    search_event = next(
        e for e in logged_events(protocol) if e["logdata"]["EVENT"] == "SEARCH"
    )
    assert search_event["logdata"]["FILTER"] == "(uid=admin)"
    assert search_event["logdata"]["ATTRIBUTES"] == ["cn"]
    assert search_event["logdata"]["SCOPE"] == 2
    assert search_event["logdata"]["BASE_OBJECT"] == "dc=example,dc=com"
    protocol.setTimeout(None)


def test_base_object_scope_returns_single_entry(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    protocol.dataReceived(bind_request(1))
    protocol.dataReceived(
        search_request(2, base=b"dc=example,dc=com", scope=0)
    )
    frames = parse_messages(protocol.transport.value())
    entry_frames = [
        frame for frame in frames if frame[0] == 2 and frame[1] == 4
    ]
    assert len(entry_frames) == 1
    assert (2, 5, 0) in frames
    protocol.setTimeout(None)


def test_single_level_scope_returns_only_children(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    protocol.dataReceived(bind_request(1))
    protocol.dataReceived(search_request(2, scope=1))
    dns = _entry_dns(protocol)
    # Direct children of the base are ou=users; the two cn entries live
    # beneath ou=users, so only ou=users matches at single level.
    assert dns == ["ou=users,dc=example,dc=com"]
    assert (2, 5, 0) in parse_messages(protocol.transport.value())
    protocol.setTimeout(None)


def test_root_dse_base_object_search(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    protocol.dataReceived(bind_request(1))
    protocol.dataReceived(search_request(2, base=b"", scope=0))
    dns = _entry_dns(protocol)
    assert dns == [""]
    protocol.setTimeout(None)


def _entry_dns(protocol):
    """Extract DNs from searchResultEntry frames in the written bytes."""
    data = protocol.transport.value()
    decoder = BERDecoder(data, 2**20)
    dns = []
    while not decoder.at_end():
        envelope = decoder.read_sequence()
        envelope.read_integer()
        tag, value, _ = envelope.read_tlv()
        if (tag & 0x1F) == 4:
            inner = BERDecoder(value, 2**20)
            dns.append(inner.read_octet_string().decode())
    return dns
# ---------------------------------------------------------------------------
# Unbind, pipelining and framing
# ---------------------------------------------------------------------------


def test_unbind_closes_connection_orderly(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    protocol.dataReceived(bind_request(1))
    protocol.dataReceived(unbind_request(2))
    assert protocol.transport.disconnecting
    # Unbind gets no response.
    assert all(frame[1] != 2 for frame in parse_messages(protocol.transport.value()))


def test_multiple_requests_in_one_segment_are_processed_in_order(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    pipeline = (
        bind_request(1)
        + search_request(2)
        + search_request(3, base=b"", scope=0)
    )
    protocol.dataReceived(pipeline)
    frames = parse_messages(protocol.transport.value())
    message_ids = [frame[0] for frame in frames]
    assert message_ids == sorted(message_ids)
    assert {1, 2, 3} <= set(message_ids)
    assert not protocol.transport.disconnecting
    protocol.setTimeout(None)


def test_fragmented_message_is_buffered_until_complete(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    request = bind_request(1, name=b"cn=admin", password=b"pw")
    protocol.dataReceived(request[:3])
    assert protocol.transport.value() == b""
    protocol.dataReceived(request[3:])
    assert parse_messages(protocol.transport.value()) == [(1, 1, 49)]
    protocol.setTimeout(None)


# ---------------------------------------------------------------------------
# Malformed input must produce a protocol error and close, never hang
# ---------------------------------------------------------------------------


def test_outer_envelope_wrong_tag_is_protocol_error(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    protocol.dataReceived(b"\x02\x01\x01")
    _assert_protocol_error_close(protocol)


def test_illegal_operation_code_is_protocol_error(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    # Application tag 99 does not exist.
    bad = encode_sequence(encode_integer(1) + tlv(0x60 + 99, b""))
    protocol.dataReceived(bad)
    _assert_protocol_error_close(protocol)


def test_illegal_protocol_version_is_protocol_error(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    protocol.dataReceived(bind_request(1, version=99))
    _assert_protocol_error_close(protocol)


def test_illegal_length_is_protocol_error(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    # SEQUENCE tag, indefinite length (forbidden in LDAP BER).
    protocol.dataReceived(b"\x30\x80\x02\x01\x01")
    _assert_protocol_error_close(protocol)


def test_truncated_frame_does_not_close_then_garbage_does(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    # Declare a 4-byte envelope but only send the first three bytes.
    protocol.dataReceived(b"\x30\x04\x02\x01")
    assert not protocol.transport.disconnecting
    assert protocol.transport.value() == b""
    # Complete the frame: valid message id then a universal-class tag where
    # an application operation is required.
    protocol.dataReceived(b"\x01\xff")
    _assert_protocol_error_close(protocol)


def test_oversized_advertised_length_closes_without_buffering(ldap_factory):
    _, connect = ldap_factory(**{"ldap.max_message_size": 32})
    protocol = connect()
    # Declare a 1000-byte envelope while sending far fewer bytes.
    protocol.dataReceived(b"\x30\x82\x03\xe8" + b"\x00" * 10)
    _assert_protocol_error_close(protocol)
    assert len(protocol._buffer) == 0


def test_oversized_input_buffer_closes(ldap_factory):
    _, connect = ldap_factory(**{"ldap.max_message_size": 16})
    protocol = connect()
    protocol.dataReceived(b"\x30\x82" + b"\x41" * 40)
    _assert_protocol_error_close(protocol)


def test_invalid_scope_is_protocol_error(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    protocol.dataReceived(bind_request(1))
    protocol.dataReceived(search_request(2, scope=9))
    _assert_protocol_error_close(protocol, allow_prior=True)


def test_malformed_filter_is_protocol_error(ldap_factory):
    _, connect = ldap_factory()
    protocol = connect()
    protocol.dataReceived(bind_request(1))
    # Equality filter whose body is not two octet strings.
    protocol.dataReceived(
        search_request(2, filter_bytes=tlv(0xA3, b"\x02\x01\x01"))
    )
    _assert_protocol_error_close(protocol, allow_prior=True)


def test_overlong_dn_is_clipped_in_log(ldap_factory):
    _, connect = ldap_factory(**{"ldap.max_value_length": 20})
    protocol = connect()
    long_dn = b"cn=" + b"a" * 200 + b",dc=example,dc=com"
    protocol.dataReceived(bind_request(1, name=long_dn, password=b"x"))
    event = logged_events(protocol)[0]
    assert len(event["logdata"]["DN"]) == 20
    assert len(event["logdata"]["PASSWORD"]) == 1
    protocol.setTimeout(None)


def _assert_protocol_error_close(protocol, allow_prior=False):
    assert protocol.transport.disconnecting
    frames = parse_messages(protocol.transport.value())
    # Unsolicited Notice of Disconnection: message id 0, extendedResponse
    # (app tag 24) carrying result code protocolError (2).
    notice = (0, 24, 2)
    if allow_prior:
        assert notice in frames
        assert frames[-1] == notice
    else:
        assert frames == [notice]
    event = logged_events(protocol)[-1]
    assert event["logdata"]["EVENT"] == "ERROR"
    assert event["logtype"] == LDAP_LOG_TYPE


# ---------------------------------------------------------------------------
# Connection limits and timeouts
# ---------------------------------------------------------------------------


def test_connection_limit_rejects_new_connections(ldap_factory):
    factory, connect = ldap_factory(**{"ldap.max_connections": 1})
    first = connect()
    second = connect()
    assert second.transport.disconnecting
    assert factory.active_connections == 1
    first.connectionLost(None)
    assert factory.active_connections == 0


def test_idle_timeout_closes_connection(ldap_factory):
    factory, connect = ldap_factory(**{"ldap.timeout": 5})
    protocol = connect()
    factory.reactor.advance(4)
    assert not protocol.transport.disconnecting
    factory.reactor.advance(2)
    assert protocol.transport.disconnecting
    assert not factory.reactor.getDelayedCalls()


def test_timeout_can_be_disabled(ldap_factory):
    factory, connect = ldap_factory(**{"ldap.timeout": 0})
    protocol = connect()
    factory.reactor.advance(3600)
    assert not protocol.transport.disconnecting
    assert not factory.reactor.getDelayedCalls()


# ---------------------------------------------------------------------------
# BER decoder unit checks
# ---------------------------------------------------------------------------


def test_decoder_rejects_indefinite_length():
    with pytest.raises(LDAPProtocolError):
        BERDecoder(b"\x30\x80\x00\x00", 1024).read_sequence()


def test_decoder_rejects_length_above_limit():
    # OCTET STRING claiming 5000 bytes inside a small buffer.
    with pytest.raises(LDAPProtocolError):
        BERDecoder(b"\x04\x82\x13\x88", 1024).read_octet_string()


def test_decoder_rejects_negative_integer():
    with pytest.raises(LDAPProtocolError):
        BERDecoder(tlv(TAG_INTEGER, b"\xff"), 1024).read_integer()
