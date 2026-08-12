#!/usr/bin/env python3
"""Deterministic Enron message parsing and record-candidate construction.

The parser intentionally handles only the RFC-5322/MIME structures used by
the frozen Enron profile.  It is strict about defects that could change a
paper result: malformed headers, transfer encodings, charsets, and text
decoding errors are reported to the caller as one ``dropped.charset_or_mime``
drop.
"""

import base64
import binascii
import codecs
import hashlib
import quopri
import re
import stat
import unicodedata
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path


_COPY_DOMAIN = b"piccard-enron-copy-v1"
_FEATURE_DOMAIN = b"piccard-real-feature-v1"
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_MESSAGE_ID_RE = re.compile(r"^<([^<>\s]+)>$", re.ASCII)
_PREFIX_RE = re.compile(r"^(?:re(?:\[[0-9]+\])?|fw|fwd):[ \t]*", re.IGNORECASE)
_ENCODED_WORD_RE = re.compile(
    r"=\?[^?\s]+\?[bBqQ]\?[^?\r\n]*\?=", re.ASCII)
_TRANSFER_ENCODINGS = frozenset({"7bit", "8bit", "binary", "base64",
                                 "quoted-printable"})


class EnronMessageError(ValueError):
    """A message cannot be admitted to the frozen parser profile."""


@dataclass(frozen=True)
class EnronParsedMessage:
    """Normalized outer headers and decoded, MIME-filtered body."""

    relative_path: str
    date: str
    from_header: str
    to: str
    cc: str
    bcc: str
    subject: str
    message_id: str
    x_folder: str
    x_origin: str
    x_filename: str
    body: str

    @property
    def from_(self) -> str:
        """Python-friendly alias for the normalized ``From`` header."""
        return self.from_header


@dataclass(frozen=True)
class EnronRecordCandidate:
    """An eligible, deduplicated document before universe bucketing/pairing."""

    relative_path: str
    date: str
    from_header: str
    to: str
    cc: str
    bcc: str
    subject: str
    message_id: str
    x_folder: str
    x_origin: str
    x_filename: str
    body: str
    canonical_subject: str
    shingles: tuple[str, ...]
    raw_features: tuple[int, ...]
    copy_fingerprint: str

    @property
    def from_(self) -> str:
        """Python-friendly alias for the normalized ``From`` header."""
        return self.from_header


def _validate_relative_path(relative_path: str) -> None:
    if (not relative_path or relative_path.startswith("/")
            or "\\" in relative_path):
        raise EnronMessageError(f"invalid relative path: {relative_path!r}")
    parts = relative_path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise EnronMessageError(f"invalid relative path: {relative_path!r}")
    if unicodedata.normalize("NFC", relative_path) != relative_path:
        raise EnronMessageError(
            f"relative path is not Unicode NFC: {relative_path!r}")


def _header_has_encoded_word_error(raw_value: str) -> bool:
    """Reject malformed RFC-2047 markers while accepting ordinary text.

    ``email.policy.default`` preserves some malformed encoded words without a
    defect object.  The frozen parser therefore validates every ``=?`` marker
    independently before accepting the normalized header value.
    """
    start = 0
    while True:
        marker = raw_value.find("=?", start)
        if marker < 0:
            return False
        match = _ENCODED_WORD_RE.match(raw_value, marker)
        if match is None:
            return True
        token = match.group(0)
        parts = token[2:-2].split("?", 2)
        if len(parts) != 3:
            return True
        charset, encoding, encoded = parts
        if (not re.fullmatch(r"[A-Za-z0-9!#$%&+\-^_`{}~.]+", charset)
                or encoding.casefold() not in ("b", "q")):
            return True
        if not encoded:
            return True
        if any(ord(character) < 33 or ord(character) > 126
               for character in encoded):
            return True
        try:
            codec = codecs.lookup(charset)
        except LookupError:
            return True
        if encoding.casefold() == "b":
            try:
                decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
                decoded.decode(codec.name, errors="strict")
            except (binascii.Error, UnicodeDecodeError, UnicodeEncodeError,
                    ValueError):
                return True
        else:
            if any(character.isspace() for character in encoded):
                return True
            if re.search(r"=(?![0-9A-Fa-f]{2})", encoded):
                return True
            try:
                decoded = quopri.decodestring(
                    encoded.replace("_", " ").encode("ascii"))
                decoded.decode(codec.name, errors="strict")
            except (binascii.Error, UnicodeDecodeError, UnicodeEncodeError,
                    ValueError):
                return True
        start = match.end()


def _normalize_header(message, name: str) -> str:
    values = message.get_all(name, [])
    if not values:
        return ""
    raw_values = [raw for header_name, raw in message.raw_items()
                  if header_name.casefold() == name.casefold()]
    # get_all() returns the policy header objects.  Inspect every object so a
    # malformed duplicate cannot be hidden behind the first value.
    normalized_values = []
    for index, value in enumerate(values):
        defects = getattr(value, "defects", ())
        if defects:
            raise EnronMessageError(f"header defect in {name}: {defects!r}")
        raw_value = raw_values[index] if index < len(raw_values) else str(value)
        if _header_has_encoded_word_error(raw_value):
            raise EnronMessageError(f"invalid RFC-2047 header: {name}")
        normalized_value = str(value)
        # HeaderRegistry normally unfolds to a tab; support both its spelling
        # and raw CRLF+WSP should a parser implementation retain the fold.
        unfolded = re.sub(r"(?:\r\n|\n)[ \t]+", " ", normalized_value)
        unfolded = re.sub(r"[\t]+", " ", unfolded)
        normalized_values.append(
            unicodedata.normalize("NFKC", unfolded).strip(" \t"))
    # The stable envelope uses one normalized header value.  The parser's
    # first-value semantics are deterministic for duplicate headers.
    return normalized_values[0]


def _validate_message_defects(message) -> None:
    defects = getattr(message, "defects", ())
    if defects:
        raise EnronMessageError(f"message parser defect: {defects!r}")
    for name in message.keys():
        values = message.get_all(name, [])
        for value in values:
            if getattr(value, "defects", ()):
                raise EnronMessageError(
                    f"header defect in {name}: {value.defects!r}")
    for name, raw_value in message.raw_items():
        if _header_has_encoded_word_error(raw_value):
            raise EnronMessageError(f"invalid RFC-2047 header: {name}")


def _decode_text_leaf(part) -> str | None:
    """Return one accepted text/plain leaf, or None for an excluded leaf."""
    _validate_message_defects(part)
    if part.get_content_type().casefold() != "text/plain":
        return None
    disposition = part.get_content_disposition()
    filename = part.get_filename()
    if disposition == "attachment" or filename not in (None, ""):
        return None

    transfer_header = part.get("Content-Transfer-Encoding", "")
    transfer = transfer_header.strip().casefold()
    if transfer == "":
        transfer = "7bit"
    if transfer not in _TRANSFER_ENCODINGS:
        raise EnronMessageError(
            f"invalid transfer encoding: {transfer_header!r}")

    raw_payload = part.get_payload(decode=False)
    if transfer in ("base64", "quoted-printable"):
        if raw_payload is None:
            raw_payload = ""
        if isinstance(raw_payload, str):
            try:
                raw_payload_bytes = raw_payload.encode("ascii")
            except UnicodeEncodeError as exc:
                raise EnronMessageError(
                    "non-ASCII transfer-encoded payload") from exc
        elif isinstance(raw_payload, bytes):
            raw_payload_bytes = raw_payload
        else:
            raise EnronMessageError("MIME payload is not bytes or text")
    else:
        raw_payload_bytes = b""
    if transfer == "base64":
        compact = re.sub(rb"[ \t\r\n]", b"", raw_payload_bytes)
        try:
            base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise EnronMessageError("invalid base64 transfer payload") from exc
    elif transfer == "quoted-printable":
        if re.search(rb"=(?![0-9A-Fa-f]{2}|\r\n|\n|\r)",
                     raw_payload_bytes):
            raise EnronMessageError("invalid quoted-printable transfer payload")

    payload = part.get_payload(decode=True)
    # email.policy.default materializes base64 defects when decode=True, so
    # this check must occur after decoding as well as before it.
    _validate_message_defects(part)
    if payload is None:
        payload = b""
    if not isinstance(payload, bytes):
        raise EnronMessageError("decoded MIME payload is not bytes")

    charset = part.get_content_charset() or "us-ascii"
    if charset.casefold() == "ansi_x3.4-1968":
        charset = "ascii"
    try:
        return payload.decode(charset, errors="strict")
    except (LookupError, UnicodeDecodeError) as exc:
        raise EnronMessageError(
            f"cannot strictly decode text/plain charset {charset!r}") from exc


def parse_message(path: Path, relative_path: str) -> EnronParsedMessage:
    """Parse and normalize one RFC-5322 message under the Enron v2 profile."""
    _validate_relative_path(relative_path)
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise EnronMessageError(f"cannot read message: {path}") from exc
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
        _validate_message_defects(message)
        headers = {
            name: _normalize_header(message, name)
            for name in ("Date", "From", "To", "Cc", "Bcc", "Subject",
                         "Message-ID", "X-Folder", "X-Origin", "X-FileName")
        }
        leaves = []
        for part in message.walk():
            if part.is_multipart():
                _validate_message_defects(part)
                continue
            decoded = _decode_text_leaf(part)
            if decoded is not None:
                leaves.append(decoded)
        body = "\n".join(leaves).replace("\r\n", "\n").replace("\r", "\n")
    except EnronMessageError:
        raise
    except (LookupError, UnicodeError, ValueError, TypeError) as exc:
        raise EnronMessageError(f"cannot parse message: {path}") from exc
    return EnronParsedMessage(
        relative_path=relative_path,
        date=headers["Date"],
        from_header=headers["From"],
        to=headers["To"],
        cc=headers["Cc"],
        bcc=headers["Bcc"],
        subject=headers["Subject"],
        message_id=headers["Message-ID"],
        x_folder=headers["X-Folder"],
        x_origin=headers["X-Origin"],
        x_filename=headers["X-FileName"],
        body=body,
    )


def copy_fingerprint(message: EnronParsedMessage) -> str:
    """Hash the stable envelope and decoded body before quote removal."""
    fields = (message.date, message.from_header, message.to, message.cc,
              message.bcc, message.subject, message.body)
    hasher = hashlib.sha256(_COPY_DOMAIN + b"\x00")
    for field in fields:
        encoded = field.encode("utf-8")
        hasher.update(len(encoded).to_bytes(4, "big"))
        hasher.update(encoded)
    return hasher.hexdigest()


def canonical_subject(subject: str) -> str:
    """Normalize subject prefixes and tokenize as ASCII words."""
    value = unicodedata.normalize("NFKC", subject).casefold().strip()
    while True:
        match = _PREFIX_RE.match(value)
        if match is None:
            break
        value = value[match.end():].lstrip(" \t")
    return " ".join(_TOKEN_RE.findall(value))


def _canonical_body(body: str) -> str:
    lines = body.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    kept = []
    for line in lines:
        if line.lstrip().startswith(">"):
            continue
        stripped = line.strip()
        if re.match(r"^[-_ \t]*original[ \t]+message[-_ \t]*$",
                    stripped, re.IGNORECASE):
            break
        if re.match(r"^on[ \t].+[ \t]+wrote:[ \t]*$", stripped,
                    re.IGNORECASE):
            break
        kept.append(line)
    cleaned = "\n".join(kept).rstrip("\n")
    if body.endswith(("\n", "\r")) and cleaned:
        cleaned += "\n"
    return cleaned


def body_shingles(body: str) -> tuple[str, ...]:
    """Return unpadded consecutive five-token canonical shingles."""
    normalized = unicodedata.normalize("NFKC", body).casefold()
    tokens = _TOKEN_RE.findall(normalized)
    return tuple("\x1f".join(tokens[index:index + 5])
                 for index in range(max(0, len(tokens) - 4)))


def _feature_hash(shingle: str) -> int:
    digest = hashlib.sha256(
        _FEATURE_DOMAIN + b"\x00" + shingle.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _iter_message_paths(maildir: Path):
    root = Path(maildir)
    if not root.is_dir() or root.is_symlink():
        raise EnronMessageError(f"maildir is not a regular directory: {root}")
    try:
        if root.stat().st_mode & 0o555 == 0:
            raise EnronMessageError(f"maildir is unreadable: {root}")
    except OSError as exc:
        raise EnronMessageError(f"cannot stat maildir: {root}") from exc
    paths = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise EnronMessageError(f"symlink in maildir: {path}")
        if path.is_dir():
            try:
                if path.stat().st_mode & 0o555 == 0:
                    raise EnronMessageError(f"unreadable maildir directory: {path}")
            except OSError as exc:
                raise EnronMessageError(f"cannot stat maildir directory: {path}") from exc
            continue
        if not path.is_file():
            raise EnronMessageError(f"non-regular maildir entry: {path}")
        try:
            file_mode = path.stat().st_mode
        except OSError as exc:
            raise EnronMessageError(f"cannot stat maildir entry: {path}") from exc
        if not stat.S_ISREG(file_mode):
            raise EnronMessageError(f"non-regular maildir entry: {path}")
        if file_mode & 0o444 == 0:
            raise EnronMessageError(f"unreadable maildir entry: {path}")
        relative = path.relative_to(root).as_posix()
        _validate_relative_path(relative)
        paths.append((relative, path))
    return sorted(paths, key=lambda item: item[0].encode("utf-8"))


def _candidate_from_message(message: EnronParsedMessage,
                            fingerprint: str) -> EnronRecordCandidate | None:
    body = _canonical_body(message.body)
    shingles = body_shingles(body)
    if not shingles:
        return None
    raw_features = tuple(sorted({_feature_hash(shingle) for shingle in shingles}))
    return EnronRecordCandidate(
        relative_path=message.relative_path,
        date=message.date,
        from_header=message.from_header,
        to=message.to,
        cc=message.cc,
        bcc=message.bcc,
        subject=message.subject,
        message_id=message.message_id,
        x_folder=message.x_folder,
        x_origin=message.x_origin,
        x_filename=message.x_filename,
        body=body,
        canonical_subject=canonical_subject(message.subject),
        shingles=shingles,
        raw_features=raw_features,
        copy_fingerprint=fingerprint,
    )


def build_record_candidates(maildir: Path):
    """Parse, deduplicate, normalize, and return sorted Enron candidates.

    The returned records are intentionally uncapped, unbucketed, and unpaired;
    document selection and pair construction belong to the next phase.
    """
    paths = _iter_message_paths(Path(maildir))
    counters = {
        "dropped.charset_or_mime": 0,
        "dropped.empty_body": 0,
        "dropped.short_body": 0,
        "dropped.duplicate_copy": 0,
        "dropped.duplicate_message_id": 0,
    }
    parsed = []
    for relative, path in paths:
        try:
            message = parse_message(path, relative)
        except EnronMessageError:
            counters["dropped.charset_or_mime"] += 1
            continue
        parsed.append((relative, message, copy_fingerprint(message)))

    by_copy = {}
    for item in parsed:
        by_copy.setdefault(item[2], []).append(item)
    copy_survivors = []
    for fingerprint, group in by_copy.items():
        del fingerprint
        group.sort(key=lambda item: item[0].encode("utf-8"))
        copy_survivors.append(group[0])
        counters["dropped.duplicate_copy"] += len(group) - 1
    copy_survivors.sort(key=lambda item: item[0].encode("utf-8"))

    by_message_id = {}
    without_message_id = []
    for item in copy_survivors:
        message_id = item[1].message_id
        match = _MESSAGE_ID_RE.fullmatch(message_id)
        if match is None:
            without_message_id.append(item)
        else:
            by_message_id.setdefault(match.group(1), []).append(item)
    id_survivors = list(without_message_id)
    for group in by_message_id.values():
        group.sort(key=lambda item: item[0].encode("utf-8"))
        id_survivors.append(group[0])
        counters["dropped.duplicate_message_id"] += len(group) - 1
    id_survivors.sort(key=lambda item: item[0].encode("utf-8"))

    candidates = []
    for _, message, fingerprint in id_survivors:
        cleaned_body = _canonical_body(message.body)
        token_count = len(_TOKEN_RE.findall(
            unicodedata.normalize("NFKC", cleaned_body).casefold()))
        if token_count == 0:
            counters["dropped.empty_body"] += 1
            continue
        if token_count < 5:
            counters["dropped.short_body"] += 1
            continue
        candidate = _candidate_from_message(message, fingerprint)
        if candidate is not None:
            candidates.append(candidate)
    candidates.sort(key=lambda item: item.relative_path.encode("utf-8"))
    return candidates, counters
