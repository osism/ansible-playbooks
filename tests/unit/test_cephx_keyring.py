import base64
import os
import struct

import pytest

import cephx_keyring
from cephx_keyring import KeyringError


def make_key(key_type=2):
    """Return a random, well-formed cephx key (never printed)."""
    length = {1: 16, 2: 32}[key_type]
    raw = struct.pack("<HIIH", key_type, 1700000000, 0, length) + os.urandom(length)
    return base64.b64encode(raw).decode()


def keyring(key, pending=None, entity="client.test"):
    lines = ["[%s]" % entity, "\tkey = %s" % key]
    if pending:
        lines.append("\tpending key = %s" % pending)
    lines.append('\tcaps mon = "allow r"')
    return "\n".join(lines) + "\n"


def test_type2_key():
    key = make_key(2)
    info, lines = cephx_keyring.parse(keyring(key), "keyring input")
    assert info["entity"] == "client.test"
    assert info["key_type"] == 2
    assert info["key_created"] == 1700000000
    assert info["has_pending"] is False
    assert info["pending_fp"] is None
    assert info["in_force_fp"] == info["key_fp"]
    assert "\tkey = %s" % key in lines


def test_type1_key():
    info, _ = cephx_keyring.parse(keyring(make_key(1)), "keyring input")
    assert info["key_type"] == 1


def test_pending_key_in_force():
    key, pending = make_key(2), make_key(2)
    info, lines = cephx_keyring.parse(keyring(key, pending), "keyring input")
    assert info["has_pending"] is True
    assert info["pending_type"] == 2
    assert info["in_force_fp"] == info["pending_fp"]
    assert info["in_force_fp"] != info["key_fp"]
    assert "\tkey = %s" % pending in lines
    assert not any("pending key" in line for line in lines)
    assert key not in "\n".join(lines)


def test_second_header_rejected():
    text = keyring(make_key()) + "[client.other]\n\tkey = %s\n" % make_key()
    with pytest.raises(KeyringError, match="exactly one"):
        cephx_keyring.parse(text, "keyring input")


@pytest.mark.parametrize("bad", ["not-base64!!", "AAAA", "A" * 40])
def test_garbage_rejected_without_key_in_message(bad):
    with pytest.raises(KeyringError) as exc:
        cephx_keyring.parse(keyring(bad), "keyring input")
    assert "not a cephx key" in str(exc.value)
    assert bad not in str(exc.value)
