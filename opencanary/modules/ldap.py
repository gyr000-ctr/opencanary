"""LDAP honeypot.

Implements enough of RFC 4511 to answer LDAP bind and search requests with
forged directory data while recording bind credentials and search filters.

The BER/DER codec is hand written so that every declared length is checked
against a fixed ceiling before the corresponding bytes are consumed. This
keeps per-connection memory bounded regardless of what a client advertises.
"""

from twisted.application import internet
from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol
from twisted.protocols.policies import TimeoutMixin

from opencanary.modules import CanaryService

# LDAP protocol operations (RFC 4511 section 4.1.1, application tags)
OP_BIND_REQUEST = 0
OP_BIND_RESPONSE = 1
OP_UNBIND_REQUEST = 2
OP_SEARCH_REQUEST = 3
OP_SEARCH_RESULT_ENTRY = 4
OP_SEARCH_RESULT_DONE = 5
OP_EXTENDED_RESPONSE = 24

# LDAP result codes (RFC 4511 section 4.1.9)
RESULT_SUCCESS = 0
RESULT_PROTOCOL_ERROR = 2
RESULT_AUTH_METHOD_NOT_SUPPORTED = 7
RESULT_INVALID_CREDENTIALS = 49

# Search scope values (RFC 4511 section 4.5.1)
SCOPE_BASE_OBJECT = 0
SCOPE_SINGLE_LEVEL = 1
SCOPE_WHOLE_SUBTREE = 2

# Notice of Disconnection extended response OID (RFC 4511 section 4.4.1)
NOTICE_OF_DISCONNECTION_OID = "1.3.6.1.4.1.1466.20036"

# BER tag classes / primitives
TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_ENUMERATED = 0x0A

DEFAULT_PORT = 389
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_CONNECTIONS = 128
# Largest single LDAP message the honeypot will buffer for a connection.
DEFAULT_MAX_MESSAGE_SIZE = 65536
# Individual OCTET STRING / OID values are clipped to this in logs.
DEFAULT_MAX_VALUE_LENGTH = 1024
# Bounded number of request attributes recorded per search.
MAX_LOGGED_ATTRIBUTES = 32
# Bounded number of fake entries returned by a search.
MAX_RETURNED_ENTRIES = 16


class LDAPProtocolError(Exception):
    """Raised when received bytes cannot be parsed as a valid LDAP message."""


class LDAPFrameIncomplete(Exception):
    """Raised while not enough bytes have arrived for the next frame."""


def _read_frame_header(data):
    """Parse a SEQUENCE tag plus BER length, returning (header_end, length)."""
    pos = 1
    try:
        first = data[pos]
    except IndexError:
        raise LDAPFrameIncomplete()
    pos += 1
    if first < 0x80:
        return pos, first
    if first == 0x80:
        # Indefinite length is not permitted in DER/LDAP messages.
        raise LDAPProtocolError("indefinite length not permitted")
    num_bytes = first & 0x7F
    if num_bytes > 4:
        raise LDAPProtocolError("length encoding too large")
    if pos + num_bytes > len(data):
        raise LDAPFrameIncomplete()
    length = 0
    for byte in data[pos : pos + num_bytes]:
        length = (length << 8) | byte
    return pos + num_bytes, length


# ---------------------------------------------------------------------------
# Minimal, length-checking BER decoder
# ---------------------------------------------------------------------------


class BERDecoder:
    """Decode BER TLVs from a byte buffer without exceeding declared limits."""

    def __init__(self, data, max_value_length=DEFAULT_MAX_VALUE_LENGTH):
        self.data = data
        self.pos = 0
        self.max_value_length = max_value_length

    def at_end(self):
        return self.pos >= len(self.data)

    def remaining(self):
        return len(self.data) - self.pos

    def read_byte(self):
        if self.pos >= len(self.data):
            raise LDAPProtocolError("truncated BER element")
        byte = self.data[self.pos]
        self.pos += 1
        return byte

    def read_length(self):
        """Read a BER length, rejecting indefinite and oversized encodings."""
        first = self.read_byte()
        if first < 0x80:
            return first
        if first == 0x80:
            # Indefinite length is not permitted in DER/LDAP messages.
            raise LDAPProtocolError("indefinite length not permitted")
        num_bytes = first & 0x7F
        if num_bytes > 4:
            raise LDAPProtocolError("length encoding too large")
        length = 0
        for _ in range(num_bytes):
            length = (length << 8) | self.read_byte()
        if length > self.max_value_length:
            raise LDAPProtocolError("element exceeds maximum length")
        return length

    def read_tlv(self, expected_tag=None):
        start = self.pos
        tag = self.read_byte()
        if expected_tag is not None and tag != expected_tag:
            raise LDAPProtocolError(
                "expected tag 0x%02x, got 0x%02x" % (expected_tag, tag)
            )
        length = self.read_length()
        if length > self.remaining():
            raise LDAPProtocolError("declared length exceeds available data")
        value_start = self.pos
        self.pos += length
        return tag, self.data[value_start : self.pos], start

    def read_sequence(self, expected_tag=TAG_SEQUENCE):
        _, value, _ = self.read_tlv(expected_tag)
        return BERDecoder(value, self.max_value_length)

    def read_integer(self, expected_tag=TAG_INTEGER):
        _, value, _ = self.read_tlv(expected_tag)
        if not value or len(value) > 8:
            raise LDAPProtocolError("invalid integer encoding")
        if value[0] & 0x80:
            # LDAP INTEGER/ENUMERATED fields used here are non-negative.
            raise LDAPProtocolError("negative integer is not permitted")
        result = 0
        for byte in value:
            result = (result << 8) | byte
        return result

    def read_boolean(self):
        _, value, _ = self.read_tlv(TAG_BOOLEAN)
        if len(value) != 1:
            raise LDAPProtocolError("invalid boolean encoding")
        return value[0] != 0

    def read_octet_string(self):
        _, value, _ = self.read_tlv(TAG_OCTET_STRING)
        return value


# ---------------------------------------------------------------------------
# Minimal BER encoder
# ---------------------------------------------------------------------------


def encode_length(length):
    if length < 0x80:
        return bytes([length])
    body = []
    while length:
        body.append(length & 0xFF)
        length >>= 8
    body.reverse()
    return bytes([0x80 | len(body)]) + bytes(body)


def encode_tlv(tag, value):
    return bytes([tag]) + encode_length(len(value)) + value


def encode_sequence(value):
    return encode_tlv(TAG_SEQUENCE, value)


def encode_integer(value, tag=TAG_INTEGER):
    if value == 0:
        body = b"\x00"
    else:
        body = []
        current = value
        while current:
            body.append(current & 0xFF)
            current >>= 8
        body.reverse()
        body = bytes(body)
        if body[0] & 0x80:
            body = b"\x00" + body
    return encode_tlv(tag, body)


def encode_octet_string(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return encode_tlv(TAG_OCTET_STRING, value)


def encode_oid(oid):
    components = [int(part) for part in oid.split(".")]
    if len(components) < 2 or components[0] > 2 or components[1] > 39:
        raise LDAPProtocolError("invalid OID")
    output = [40 * components[0] + components[1]]
    for component in components[2:]:
        if component < 0:
            raise LDAPProtocolError("invalid OID component")
        chunks = [component & 0x7F]
        component >>= 7
        while component:
            chunks.append(0x80 | (component & 0x7F))
            component >>= 7
        chunks.reverse()
        output.extend(chunks)
    return encode_tlv(TAG_OID, bytes(output))


# ---------------------------------------------------------------------------
# Search filter parsing and rendering
# ---------------------------------------------------------------------------

# Filter choice tags (RFC 4511 section 4.5.1), context-specific constructed
FILTER_AND = 0xA0
FILTER_OR = 0xA1
FILTER_NOT = 0xA2
FILTER_EQUALITY = 0xA3
FILTER_SUBSTRINGS = 0xA4
FILTER_PRESENT = 0x87
FILTER_GREATER_OR_EQUAL = 0xA5
FILTER_LESS_OR_EQUAL = 0xA6
FILTER_APPROX_MATCH = 0xA8


def _decode_text(value):
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("utf-8", errors="replace")


_ASSERTION_TAGS = {
    FILTER_EQUALITY: "=",
    FILTER_GREATER_OR_EQUAL: ">=",
    FILTER_LESS_OR_EQUAL: "<=",
    FILTER_APPROX_MATCH: "~=",
}

_SUBSTRING_TAGS = {
    0x80: lambda text: text,  # initial
    0x81: lambda text: "*%s*" % text,  # any
    0x82: lambda text: "*%s" % text,  # final
}


def _render_assertion(tag_name, value):
    decoder = BERDecoder(value)
    attribute = _decode_text(decoder.read_octet_string())
    assertion = _decode_text(decoder.read_octet_string())
    if not decoder.at_end():
        raise LDAPProtocolError("trailing bytes in assertion")
    return "(%s%s%s)" % (attribute, tag_name, assertion)


def _render_aggregation(tag, value):
    joiner = "&" if tag == FILTER_AND else "|"
    decoder = BERDecoder(value)
    rendered = []
    while not decoder.at_end():
        child_tag, child_value, _ = decoder.read_tlv()
        rendered.append(_render_filter(child_tag, child_value))
    return "(%s%s)" % (joiner, "".join(rendered))


def _render_not(value):
    decoder = BERDecoder(value)
    child_tag, child_value, _ = decoder.read_tlv()
    if not decoder.at_end():
        raise LDAPProtocolError("trailing bytes in not filter")
    return "(!%s)" % _render_filter(child_tag, child_value)


def _render_substrings(value):
    decoder = BERDecoder(value)
    attribute = _decode_text(decoder.read_octet_string())
    # SubstringFilter ::= SEQUENCE { substrings SEQUENCE OF CHOICE }
    inner = decoder.read_sequence()
    parts = []
    while not inner.at_end():
        sub_tag, sub_value, _ = inner.read_tlv()
        formatter = _SUBSTRING_TAGS.get(sub_tag)
        if formatter is None:
            raise LDAPProtocolError("unknown substring component")
        parts.append(formatter(_decode_text(sub_value)))
    if not decoder.at_end():
        raise LDAPProtocolError("trailing bytes in substrings")
    if not parts:
        raise LDAPProtocolError("empty substrings filter")
    return "(%s=%s)" % (attribute, "".join(parts))


def _render_filter(tag, value):
    if tag in (FILTER_AND, FILTER_OR):
        return _render_aggregation(tag, value)
    if tag == FILTER_NOT:
        return _render_not(value)
    if tag in _ASSERTION_TAGS:
        return _render_assertion(_ASSERTION_TAGS[tag], value)
    if tag == FILTER_PRESENT:
        return "(%s=*)" % _decode_text(value)
    if tag == FILTER_SUBSTRINGS:
        return _render_substrings(value)
    raise LDAPProtocolError("unsupported search filter tag 0x%02x" % tag)


def _render_filter(tag, value):
    if tag in (FILTER_AND, FILTER_OR):
        return _render_aggregation(tag, value)
    if tag == FILTER_NOT:
        return _render_not(value)
    if tag in _ASSERTION_TAGS:
        return _render_assertion(_ASSERTION_TAGS[tag], value)
    if tag == FILTER_PRESENT:
        return "(%s=*)" % _decode_text(value)
    if tag == FILTER_SUBSTRINGS:
        return _render_substrings(value)
    raise LDAPProtocolError("unsupported search filter tag 0x%02x" % tag)


def decode_attribute_selection(decoder):
    # AttributeSelection ::= SEQUENCE OF selector LDAPString
    selection = decoder.read_sequence()
    attributes = []
    while not selection.at_end():
        if len(attributes) >= MAX_LOGGED_ATTRIBUTES:
            raise LDAPProtocolError("too many requested attributes")
        attributes.append(_decode_text(selection.read_octet_string()))
    return attributes


# ---------------------------------------------------------------------------
# Protocol handling
# ---------------------------------------------------------------------------


class LDAPProtocol(Protocol, TimeoutMixin):
    def connectionMade(self):
        self._buffer = b""
        self._discarding = False
        self._counted_connection = False

        max_connections = self.factory.max_connections
        if max_connections is not None and max_connections > 0:
            if self.factory.active_connections >= max_connections:
                self._logError("max connections exceeded")
                self.transport.loseConnection()
                return
            self.factory.active_connections += 1
            self._counted_connection = True

        timeout = self.factory.timeout
        if timeout == 0:
            timeout = None
        self.setTimeout(timeout)

    def connectionLost(self, reason):
        self.setTimeout(None)
        if self._counted_connection:
            self.factory.active_connections = max(
                0, self.factory.active_connections - 1
            )
            self._counted_connection = False

    def callLater(self, period, func):
        return self.factory.reactor.callLater(period, func)

    def timeoutConnection(self):
        # Idle connections are dropped silently; nothing is written.
        self.setTimeout(None)
        self.transport.loseConnection()

    def dataReceived(self, data):
        if self._discarding:
            return
        self.resetTimeout()

        # Bound the buffered bytes before appending so a peer advertising
        # huge lengths cannot grow memory without limit.
        if len(self._buffer) + len(data) > self.factory.max_message_size:
            self._protocolErrorAndClose("request buffer too large")
            return
        self._buffer += data

        while self._buffer:
            try:
                message, remainder = self._extractMessage(self._buffer)
                if message is None:
                    # Full frame has not arrived yet; keep waiting.
                    return
                self._buffer = remainder
                should_close = self._handleMessage(message)
            except LDAPFrameIncomplete:
                return
            except LDAPProtocolError as error:
                self._protocolErrorAndClose(str(error))
                return
            except (IndexError, ValueError, UnicodeError):
                # Defensive: any malformed element still closes cleanly.
                self._protocolErrorAndClose("malformed LDAP message")
                return
            if should_close:
                self.setTimeout(None)
                self.transport.loseConnection()
                return

    def _decoder(self, data):
        # The whole frame is already bounded by max_message_size; use that as
        # the element ceiling so a nested length cannot exceed the frame.
        return BERDecoder(data, self.factory.max_message_size)

    def _extractMessage(self, data):
        """Return (message_bytes, remainder) or (None, data) when incomplete."""
        if not data:
            return None, data
        if data[0] != TAG_SEQUENCE:
            raise LDAPProtocolError("outer envelope is not a SEQUENCE")
        try:
            pos, length = _read_frame_header(data)
        except LDAPFrameIncomplete:
            return None, data
        if length > self.factory.max_message_size:
            raise LDAPProtocolError("frame exceeds maximum message size")
        frame_end = pos + length
        if frame_end > len(data):
            return None, data
        return data[:frame_end], data[frame_end:]

    @staticmethod
    def _application_tag(tag):
        """Return the application tag number or raise for a wrong tag class."""
        # Application tags are class 01: primitive 0x40+n, constructed 0x60+n.
        if tag & 0xC0 not in (0x40, 0x60):
            raise LDAPProtocolError(
                "operation uses invalid BER tag class 0x%02x" % tag
            )
        return tag & 0x1F

    def _handleMessage(self, message):
        decoder = self._decoder(message)
        envelope = decoder.read_sequence()
        message_id = envelope.read_integer()
        if message_id < 0 or message_id > 2**31 - 1:
            raise LDAPProtocolError("message id out of range")
        tag, operation, _ = envelope.read_tlv()
        if not envelope.at_end():
            # Optional controls are not supported; reject rather than ignore.
            raise LDAPProtocolError("trailing bytes in LDAP message")

        application_tag = self._application_tag(tag)

        if application_tag == OP_BIND_REQUEST:
            self._handleBind(message_id, operation)
            return False
        if application_tag == OP_UNBIND_REQUEST:
            # Unbind has empty body and requests an orderly close.
            if operation:
                raise LDAPProtocolError("unbind request must be empty")
            return True
        if application_tag == OP_SEARCH_REQUEST:
            self._handleSearch(message_id, operation)
            return False
        raise LDAPProtocolError(
            "unsupported operation code %d" % application_tag
        )

    # -- Bind --------------------------------------------------------------

    def _handleBind(self, message_id, operation):
        decoder = self._decoder(operation)
        version = decoder.read_integer()
        # Only LDAPv3 is offered; any other version is a protocol violation.
        if version != 3:
            raise LDAPProtocolError("unsupported LDAP protocol version %d" % version)
        name = decoder.read_octet_string()
        # Authentication is a CHOICE; only the simple [0] primitive is offered.
        auth_tag, auth_value, _ = decoder.read_tlv()
        if not decoder.at_end():
            raise LDAPProtocolError("trailing bytes in bind request")

        if auth_tag != 0x80:
            # SASL ([1]) and any other choice are not offered by the honeypot.
            self._sendBindResponse(message_id, RESULT_AUTH_METHOD_NOT_SUPPORTED)
            self._logBind(
                name,
                b"",
                version,
                result=RESULT_AUTH_METHOD_NOT_SUPPORTED,
                anonymous=not name,
            )
            return

        password = auth_value
        anonymous = not name and not password
        if anonymous:
            result_code = RESULT_SUCCESS
        else:
            # Every credentialed bind is rejected, but the DN and password
            # are captured first via the standard honeycred mechanism.
            result_code = RESULT_INVALID_CREDENTIALS
        self._sendBindResponse(message_id, result_code)
        self._logBind(
            name,
            password,
            version,
            result=result_code,
            anonymous=anonymous,
        )

    def _sendBindResponse(self, message_id, result_code):
        # BindResponse ::= [APPLICATION 1] SEQUENCE { LDAPResult components }
        result = (
            encode_integer(result_code, TAG_ENUMERATED)
            + encode_octet_string(b"")
            + encode_octet_string(b"")
        )
        body = encode_tlv(0x40 + OP_BIND_RESPONSE + 0x20, result)
        self._sendMessage(
            encode_sequence(encode_integer(message_id) + body)
        )

    def _logBind(self, name, password, version, result, anonymous):
        logdata = {
            "EVENT": "BIND",
            "VERSION": version,
            "DN": self._decode_for_log(name),
            "USERNAME": self._decode_for_log(name),
            "PASSWORD": self._decode_for_log(password),
            "RESULT": result,
            "ANONYMOUS": anonymous,
        }
        self.factory.log(logdata, transport=self.transport)

    # -- Search ------------------------------------------------------------

    def _handleSearch(self, message_id, operation):
        decoder = self._decoder(operation)
        base_object = decoder.read_octet_string()
        scope = decoder.read_integer(TAG_ENUMERATED)
        if scope not in (
            SCOPE_BASE_OBJECT,
            SCOPE_SINGLE_LEVEL,
            SCOPE_WHOLE_SUBTREE,
        ):
            raise LDAPProtocolError("invalid search scope %d" % scope)
        deref_aliases = decoder.read_integer(TAG_ENUMERATED)
        if not 0 <= deref_aliases <= 3:
            raise LDAPProtocolError("invalid alias dereference policy")
        size_limit = decoder.read_integer()
        decoder.read_integer()  # timeLimit: accepted but not enforced
        types_only = decoder.read_boolean()
        filter_tag, filter_value, _ = decoder.read_tlv()
        filter_text = _render_filter(filter_tag, filter_value)
        requested_attributes = decode_attribute_selection(decoder)

        entries = self.factory.entries_for_search(
            base_object,
            scope,
            limit=size_limit if size_limit > 0 else MAX_RETURNED_ENTRIES,
        )

        for entry_dn, attributes in entries:
            self._sendSearchEntry(
                message_id, entry_dn, attributes, requested_attributes, types_only
            )
        self._sendSearchResultDone(message_id, RESULT_SUCCESS)

        self._logSearch(base_object, scope, filter_text, requested_attributes)

    def _sendSearchEntry(self, message_id, dn, attributes, requested, types_only):
        attribute_sequence = b""
        for name, values in attributes:
            if requested and name not in requested and "*" not in requested:
                continue
            values_sequence = b""
            if not types_only:
                for value in values:
                    values_sequence += encode_octet_string(value)
            partial = encode_octet_string(name) + encode_sequence(values_sequence)
            attribute_sequence += encode_sequence(partial)
        # SearchResultEntry ::= [APPLICATION 4] SEQUENCE (constructed tag)
        body = encode_tlv(
            0x60 + OP_SEARCH_RESULT_ENTRY,
            encode_octet_string(dn) + encode_sequence(attribute_sequence),
        )
        self._sendMessage(encode_sequence(encode_integer(message_id) + body))

    def _sendSearchResultDone(self, message_id, result_code):
        # SearchResultDone ::= [APPLICATION 5] SEQUENCE { LDAPResult components }
        result = (
            encode_integer(result_code, TAG_ENUMERATED)
            + encode_octet_string(b"")
            + encode_octet_string(b"")
        )
        body = encode_tlv(0x40 + OP_SEARCH_RESULT_DONE + 0x20, result)
        self._sendMessage(encode_sequence(encode_integer(message_id) + body))

    def _logSearch(self, base_object, scope, filter_text, requested_attributes):
        logdata = {
            "EVENT": "SEARCH",
            "BASE_OBJECT": self._decode_for_log(base_object),
            "SCOPE": scope,
            "FILTER": self._clip(filter_text),
            "ATTRIBUTES": requested_attributes,
        }
        self.factory.log(logdata, transport=self.transport)

    # -- Errors ------------------------------------------------------------

    def _protocolErrorAndClose(self, reason):
        if self._discarding:
            return
        self._discarding = True
        self._buffer = b""
        self._sendNoticeOfDisconnection()
        self._logError(reason)
        self.setTimeout(None)
        self.transport.loseConnection()

    def _sendNoticeOfDisconnection(self):
        # Unsolicited Notification of Disconnection (RFC 4511 4.4.1) uses
        # message id 0 and carries the protocolError result code.
        result = (
            encode_integer(RESULT_PROTOCOL_ERROR, TAG_ENUMERATED)
            + encode_octet_string(b"")
            + encode_octet_string(b"protocol error")
            + encode_oid(NOTICE_OF_DISCONNECTION_OID)
        )
        # ExtendedResponse ::= [APPLICATION 24] SEQUENCE
        body = encode_tlv(0x40 + OP_EXTENDED_RESPONSE + 0x20, result)
        self._sendMessage(encode_sequence(encode_integer(0) + body))

    def _logError(self, reason):
        logdata = {"EVENT": "ERROR", "ERROR": self._clip(reason)}
        self.factory.log(logdata, transport=self.transport)

    # -- Helpers -----------------------------------------------------------

    def _sendMessage(self, payload):
        self.transport.write(payload)

    def _decode_for_log(self, value):
        return self._clip(value.decode("utf-8", errors="replace"))

    def _clip(self, text):
        if len(text) > self.factory.max_value_length:
            return text[: self.factory.max_value_length]
        return text


# Fixed, small fake directory. Kept on the factory so it is shared read-only
# across connections; per-connection state never caches directory data.
DEFAULT_ENTRIES = [
    (
        "",
        [
            ("namingContexts", [b"dc=example,dc=com"]),
            ("supportedLDAPVersion", [b"3"]),
            ("supportedExtension", [b"1.3.6.1.4.1.1466.20037"]),
        ],
    ),
    (
        "dc=example,dc=com",
        [
            ("dc", [b"example"]),
            ("objectClass", [b"top", b"domain"]),
        ],
    ),
    (
        "ou=users,dc=example,dc=com",
        [
            ("ou", [b"users"]),
            ("objectClass", [b"top", b"organizationalUnit"]),
        ],
    ),
    (
        "cn=admin,ou=users,dc=example,dc=com",
        [
            ("cn", [b"admin"]),
            ("uid", [b"admin"]),
            ("objectClass", [b"top", b"person", b"organizationalPerson"]),
            ("mail", [b"admin@example.com"]),
        ],
    ),
    (
        "cn=guest,ou=users,dc=example,dc=com",
        [
            ("cn", [b"guest"]),
            ("uid", [b"guest"]),
            ("objectClass", [b"top", b"person", b"organizationalPerson"]),
            ("mail", [b"guest@example.com"]),
        ],
    ),
]


class CanaryLDAP(Factory, CanaryService):
    NAME = "ldap"
    protocol = LDAPProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.port = int(config.getVal("ldap.port", default=DEFAULT_PORT))
        self.timeout = float(
            config.getVal("ldap.timeout", default=DEFAULT_TIMEOUT)
        )
        self.max_connections = int(
            config.getVal(
                "ldap.max_connections", default=DEFAULT_MAX_CONNECTIONS
            )
        )
        self.max_message_size = int(
            config.getVal(
                "ldap.max_message_size", default=DEFAULT_MAX_MESSAGE_SIZE
            )
        )
        self.max_value_length = int(
            config.getVal(
                "ldap.max_value_length", default=DEFAULT_MAX_VALUE_LENGTH
            )
        )
        base_dn = config.getVal(
            "ldap.base_dn", default="dc=example,dc=com"
        )
        self.base_dn = base_dn
        self.active_connections = 0
        self.reactor = reactor
        self.logtype = logger.LOG_LDAP_REQUEST
        self._entries = self._build_entries(base_dn)

    @staticmethod
    def _build_entries(base_dn):
        # Rebase the default directory onto the configured base DN. The list
        # stays small and constant-sized regardless of connection count.
        entries = []
        for dn, attributes in DEFAULT_ENTRIES:
            if dn == "":
                rebased_dn = ""
                attributes = [
                    (name, [base_dn.encode()] if name == "namingContexts" else value)
                    for name, value in attributes
                ]
            elif dn == "dc=example,dc=com":
                rebased_dn = base_dn
            else:
                rebased_dn = dn.replace("dc=example,dc=com", base_dn)
            entries.append((rebased_dn, attributes))
        return entries

    def entries_for_search(self, base_object, scope, limit):
        try:
            base_text = base_object.decode("utf-8")
        except UnicodeDecodeError:
            base_text = base_object.decode("utf-8", errors="replace")

        if scope == SCOPE_BASE_OBJECT:
            return self._base_object_entries(base_text)
        return self._scoped_entries(base_text, scope, limit)

    def _base_object_entries(self, base_text):
        for dn, attributes in self._entries:
            if dn.lower() == base_text.lower():
                return [(dn, attributes)]
        return []

    def _scoped_entries(self, base_text, scope, limit):
        results = []
        base_lower = base_text.lower()
        for dn, attributes in self._entries:
            # The root DSE (empty DN) is only addressable via a baseObject
            # search handled above; never part of subtree/one-level results.
            if dn == "" or not self._entry_in_scope(dn, base_lower, scope):
                continue
            results.append((dn, attributes))
            if len(results) >= min(limit, MAX_RETURNED_ENTRIES):
                break
        return results

    @staticmethod
    def _entry_in_scope(dn, base_lower, scope):
        dn_lower = dn.lower()
        if scope == SCOPE_SINGLE_LEVEL:
            parent = dn.split(",", 1)[1] if "," in dn else ""
            return parent.lower() == base_lower
        # wholeSubtree: the base itself plus everything beneath it.
        return dn_lower == base_lower or dn_lower.endswith("," + base_lower)

    def getService(self):
        return internet.TCPServer(self.port, self, interface=self.listen_addr)
