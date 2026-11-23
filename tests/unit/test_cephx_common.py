import base64
import json
import os
import struct

import pytest
from ansible.errors import AnsibleFilterError

from cephx_common import (
    FilterModule,
    _a,
    _check_fields,
    _cmd,
    _fsid,
    _guarded,
    _keyring_of,
    _loop,
    _loop_failures,
    _osd_map,
    _read,
    _records,
    _state,
    cephx_auth_export,
    cephx_failed,
    cephx_mask,
    cephx_pg_states,
    cephx_pgs_clean,
)


def key(type_=2):
    """A random key of the given type (1: aes, 2: aes256k), never printed."""
    secret = os.urandom(16 * type_)
    header = struct.pack("<HIIH", type_, 1700000000, 0, len(secret))
    return base64.b64encode(header + secret).decode()


def test_filters_registered():
    filters = FilterModule().filters()
    assert filters["cephx_mask"].__wrapped__ is cephx_mask
    assert filters["cephx_auth_export"].__wrapped__ is cephx_auth_export
    assert filters["cephx_pgs_clean"].__wrapped__ is cephx_pgs_clean
    assert filters["cephx_pg_states"].__wrapped__ is cephx_pg_states
    assert filters["cephx_failed"].__wrapped__ is cephx_failed


# cephx_failed: a failed command as the plays show it (T-4).


def test_failed_with_stderr_masked():
    k = key()
    r = {"rc": 22, "stdout": "", "stderr": "Error EINVAL: bad key %s\n" % k}
    assert cephx_failed(r, "ceph fsid") == (
        "failed (rc 22): Error EINVAL: bad key <key>"
    )


@pytest.mark.parametrize("stderr", ["", "  \n", None])
def test_failed_without_stderr(stderr):
    r = {"rc": 5, "stdout": "", "stderr": stderr}
    assert cephx_failed(r, "lvs on node-0") == "failed (rc 5)"


def test_failed_without_stderr_field():
    assert cephx_failed({"rc": 5, "stdout": ""}, "lvs") == "failed (rc 5)"


def test_failed_rc_0_is_empty():
    assert cephx_failed({"rc": 0, "stdout": "x", "stderr": "warn"}, "ceph fsid") == ""


def test_failed_ignores_the_failed_flag():
    # failed_when: false clears it; rc decides.
    r = {"rc": 1, "stdout": "", "stderr": "", "failed": False}
    assert cephx_failed(r, "ceph fsid") == "failed (rc 1)"


@pytest.mark.parametrize(
    "result, message",
    [
        ({"skipped": True}, "ceph fsid: the command was skipped"),
        ({"stdout": ""}, "ceph fsid: the result has no rc"),
        ({"rc": "1", "stdout": ""}, "ceph fsid: rc is not an int"),
        ("x", "ceph fsid: the result is not a mapping"),
    ],
)
def test_failed_unexpected_result_stops(result, message):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_failed(result, "ceph fsid")
    assert str(e.value) == message


def test_mask_aes():
    k = key(1)
    assert len(k) == 40
    assert cephx_mask("Error EINVAL: bad key %s here" % k) == (
        "Error EINVAL: bad key <key> here"
    )


def test_mask_aes256k():
    k = key(2)
    assert len(k) == 60
    assert cephx_mask("%s\n%s" % (k, k)) == "<key>\n<key>"


def test_mask_leaves_neighbours():
    k1, k2 = key(1), key(2)
    longer = [
        "x" + k1,
        k1 + "A",
        k1 + "=",
        "/" + k2,
        k2 + "=",
        k2 + "0",
        base64.b64encode(os.urandom(90)).decode(),
    ]
    for text in longer:
        assert cephx_mask(text) == text
    assert cephx_mask("(%s), '%s'" % (k1, k2)) == "(<key>), '<key>'"


def test_mask_not_text():
    assert cephx_mask(None) == "None"
    assert cephx_mask(22) == "22"


def export(entries, wrap=None):
    return json.dumps(entries if wrap is None else {wrap: entries})


def test_auth_export_auth_list():
    out = cephx_auth_export(export([{"entity": "client.a", "key": key()}], "auth"))
    assert out == {"client.a": {"pending": False, "aes": False}}


def test_auth_export_auth_dump_list():
    out = cephx_auth_export(
        export([{"entity": "client.a", "key": key(1)}], "auth_dump")
    )
    assert out == {"client.a": {"pending": False, "aes": True}}


def test_auth_export_bare_list():
    out = cephx_auth_export(
        export(
            [{"entity": "client.a", "key": key()}, {"entity": "osd.0", "key": key()}]
        )
    )
    assert list(out) == ["client.a", "osd.0"]


def test_auth_export_auth_wins_over_auth_dump():
    text = json.dumps(
        {
            "auth": [{"entity": "client.a", "key": key()}],
            "auth_dump": [{"entity": "client.b", "key": key()}],
        }
    )
    assert list(cephx_auth_export(text)) == ["client.a"]


def test_auth_export_mapping_without_lists():
    assert cephx_auth_export('{"other": []}') == {}
    assert cephx_auth_export("[]") == {}


def test_auth_export_pending_and_aes():
    entries = [
        # aes key, aes256k pending: the key in force next is aes256k
        {"entity": "client.a", "key": key(1), "pending_key": key(2)},
        # aes256k key, aes pending
        {"entity": "client.b", "key": key(2), "pending_key": key(1)},
        # empty pending key: none
        {"entity": "client.c", "key": key(1), "pending_key": ""},
        # no key at all
        {"entity": "client.d"},
        {"entity": "client.e", "key": key(2)},
    ]
    assert cephx_auth_export(export(entries)) == {
        "client.a": {"pending": True, "aes": False},
        "client.b": {"pending": True, "aes": True},
        "client.c": {"pending": False, "aes": True},
        "client.d": {"pending": False, "aes": False},
        "client.e": {"pending": False, "aes": False},
    }


def test_auth_export_garbage_message_has_no_input():
    k = key()
    garbage = [
        "",
        "not json %s" % k,
        '{"auth": [{"entity": "client.a", "key": "%s"}' % k,
        json.dumps({"auth": k}),
        json.dumps({"auth": None}),
        json.dumps({"auth": "x", "auth_dump": [{"entity": "client.a", "key": k}]}),
        json.dumps([{"entity": "client.a", "key": k}, {"key": k}]),
        json.dumps([{"entity": "client.a", "key": k}, k]),
        json.dumps([{"entity": 3, "key": k}]),
        json.dumps(k),
        json.dumps(3),
        None,
    ]
    for text in garbage:
        with pytest.raises(AnsibleFilterError) as e:
            cephx_auth_export(text)
        assert str(e.value) == "ceph auth export did not print JSON"
        assert k not in str(e.value)


def pg_stat(states, num_pgs=33):
    return json.dumps(
        {
            "pg_ready": True,
            "pg_summary": {
                "num_pg_by_state": [{"name": n, "num": c} for n, c in states],
                "num_pgs": num_pgs,
            },
        }
    )


def test_pgs_clean_all():
    assert cephx_pgs_clean(pg_stat([("active+clean", 33)])) is True
    assert cephx_pgs_clean(pg_stat([("active+clean", 0)], 0)) is True


def test_pgs_clean_undersized():
    stdout = pg_stat([("active+clean", 0), ("active+undersized", 33)])
    assert cephx_pgs_clean(stdout) is False
    assert cephx_pgs_clean(pg_stat([("active+clean", 32)])) is False
    for unreadable in ("", "Error", "[]", "{}", '{"pg_summary": {}}', "{", None):
        assert cephx_pgs_clean(unreadable) is False


def test_pg_states_text():
    stdout = pg_stat([("active+clean", 0), ("active+undersized", 33)])
    assert cephx_pg_states(stdout) == "0 active+clean, 33 active+undersized"
    assert cephx_pg_states(pg_stat([("active+clean", 33)])) == "33 active+clean"
    for unreadable in ("", "Error", "[]", "{}", '{"pg_summary": []}', "{", None):
        assert cephx_pg_states(unreadable) == ""


def test_plugins_share_one_common_module():
    # Every plugin loads cephx_common.py by its path under one name: the
    # helpers have one home.
    import sys

    import cephx_lockbox
    import cephx_redeploy
    import cephx_rotate
    import cephx_rotate_texts
    import cephx_validate

    common = sys.modules["_cephx_common"]
    for plugin in (
        cephx_lockbox,
        cephx_redeploy,
        cephx_rotate,
        cephx_rotate_texts,
        cephx_validate,
    ):
        assert plugin._common is common
        assert plugin._guarded is common._guarded
    assert common.FilterModule().filters().keys() == FilterModule().filters().keys()


# The input boundary: _state, _cmd, _loop, _records, _guarded


def test_state_envelopes():
    assert _state({"skipped": True, "changed": False}) == "skipped"
    assert _state({"unreachable": True, "msg": "ssh"}) == "unreachable"
    assert _state({"failed": True, "msg": "module failed"}) == "failed"
    assert _state({"changed": False, "stat": {"exists": True}}) == "ok"
    # failed_when: false clears `failed`: the command's rc is the caller's
    # check, the envelope is ok.
    ok_rc1 = {"failed": False, "rc": 1, "stdout": "", "stderr": "Error"}
    assert _state(ok_rc1) == "ok"
    assert _cmd(ok_rc1, "ceph fsid")["rc"] == 1
    # Skipped wins over the other flags of a skipped loop item.
    assert _state({"skipped": True, "failed": False}) == "skipped"
    assert _state({"skipped": False, "failed": False}) == "ok"


def test_state_refuses_what_is_not_a_result():
    for result in (None, "ok", [], {"failed": "yes"}, {"skipped": 1}):
        with pytest.raises(AnsibleFilterError):
            _state(result)


def test_cmd_requires_fields():
    good = {"rc": 0, "stdout": "x", "stderr": ""}
    assert _cmd(good, "ceph fsid") is good
    assert _cmd({"rc": 0, "stdout": "", "stderr": None}, "ceph fsid")["rc"] == 0
    # A failed command is the caller's to judge by its rc.
    failed = {"failed": True, "rc": 2, "stdout": "", "stderr": "Error"}
    assert _cmd(failed, "ceph fsid") is failed
    cases = [
        (None, "ceph fsid: the result is not a mapping"),
        ({"stdout": "", "stderr": ""}, "ceph fsid: the result has no rc"),
        ({"rc": 0, "stderr": ""}, "ceph fsid: the result has no stdout"),
        ({"rc": "0", "stdout": "", "stderr": ""}, "ceph fsid: rc is not an int"),
        ({"rc": True, "stdout": "", "stderr": ""}, "ceph fsid: rc is not an int"),
        ({"rc": 0, "stdout": 1, "stderr": ""}, "ceph fsid: stdout is not a str"),
        ({"rc": 0, "stdout": "", "stderr": 1}, "ceph fsid: stderr is not a str"),
        ({"skipped": True}, "ceph fsid: the command was skipped"),
        ({"unreachable": True}, "ceph fsid: the host was unreachable"),
    ]
    for result, message in cases:
        with pytest.raises(AnsibleFilterError) as err:
            _cmd(result, "ceph fsid")
        assert str(err.value) == message


def test_loop_requires_items():
    registered = {"results": [{"item": "crash", "rc": 0}, {"item": "rgw"}]}
    assert _loop(registered, "ceph orch ps") == registered["results"]
    assert _loop({"results": []}, "ceph orch ps") == []
    cases = [
        (None, "ceph orch ps: the result is not a mapping"),
        ({}, "ceph orch ps: the result has no results"),
        ({"results": {}}, "ceph orch ps: the results are not a list"),
        ({"results": ["x"]}, "ceph orch ps: a result is not a mapping"),
        ({"results": [{"rc": 0}]}, "ceph orch ps: a result has no item"),
    ]
    for registered, message in cases:
        with pytest.raises(AnsibleFilterError) as err:
            _loop(registered, "ceph orch ps")
        assert str(err.value) == message


def test_records_checks_fields():
    required = {"daemon_name": str, "rc": int}
    text = json.dumps([{"daemon_name": "crash.a", "rc": 0, "extra": None}])
    assert _records(text, "ceph orch ps", list, required) == json.loads(text)
    obj = json.dumps({"daemon_name": "crash.a", "rc": 0})
    assert _records(obj, "ceph osd find", dict, required) == json.loads(obj)
    assert _records("[]", "ceph orch ps", list, required) == []
    assert _records('{"a": 1}', "x", dict, {}) == {"a": 1}
    # A field may name several types.
    assert _records('[{"v": null}]', "x", list, {"v": (str, type(None))}) == [
        {"v": None}
    ]
    cases = [
        ("", "ceph orch ps: did not print JSON"),
        ("Error", "ceph orch ps: did not print JSON"),
        (None, "ceph orch ps: did not print JSON"),
        ('"x"', "ceph orch ps: did not print a JSON list"),
        ('{"daemon_name": "a", "rc": 0}', "ceph orch ps: did not print a JSON list"),
        ("[1]", "ceph orch ps: an entry is not an object"),
        ('[{"rc": 0}]', "ceph orch ps: an entry has no daemon_name"),
        ('[{"daemon_name": 1, "rc": 0}]', "ceph orch ps: daemon_name is not a str"),
        ('[{"daemon_name": "a", "rc": true}]', "ceph orch ps: rc is not an int"),
        ('[{"daemon_name": "a", "rc": 1.0}]', "ceph orch ps: rc is not an int"),
    ]
    for text, message in cases:
        with pytest.raises(AnsibleFilterError) as err:
            _records(text, "ceph orch ps", list, required)
        assert str(err.value) == message
    # One object: its fields are the object's, not an entry's.
    cases = [
        ('"x"', "ceph osd dump: did not print a JSON object"),
        ("[]", "ceph osd dump: did not print a JSON object"),
        ("{}", "ceph osd dump: the object has no osds"),
        ('{"osds": {}}', "ceph osd dump: osds is not a list"),
    ]
    for text, message in cases:
        with pytest.raises(AnsibleFilterError) as err:
            _records(text, "ceph osd dump", dict, {"osds": list})
        assert str(err.value) == message
    with pytest.raises(AnsibleFilterError) as err:
        _records('[{"v": 1}]', "x", list, {"v": (str, type(None))})
    assert str(err.value) == "x: v is not a str or NoneType"
    with pytest.raises(AnsibleFilterError) as err:
        _records('[{"v": 1}]', "x", list, {"v": bool})
    assert str(err.value) == "x: v is not a bool"


def test_records_messages_never_carry_values():
    k = key()
    inputs = [
        ("not json " + k, list, {"daemon_name": str}),
        ('{"key": "%s"' % k, dict, {"daemon_name": str}),
        (json.dumps(k), list, {"daemon_name": str}),
        (json.dumps(k), dict, {"daemon_name": str}),
        (json.dumps([k]), list, {"daemon_name": str}),
        (json.dumps([{k: 1}]), list, {"daemon_name": str}),
        (json.dumps([{"daemon_name": k}]), list, {"daemon_name": int}),
        (json.dumps({"daemon_name": k}), dict, {"daemon_name": list}),
        (json.dumps({k: 1}), dict, {"daemon_name": str}),
    ]
    for text, shape, required in inputs:
        with pytest.raises(AnsibleFilterError) as err:
            _records(text, "ceph auth get", shape, required)
        assert k not in str(err.value)
        assert k not in repr(err.value)
        assert err.value.__cause__ is None
        assert err.value.__context__ is None


# The shared reads: _read, _fsid, _keyring_of, _loop_failures, _osd_map,
# _check_fields


def test_read():
    def check(stdout):
        return "" if stdout == "ok" else "did not print ok"

    ok = {"rc": 0, "stdout": "ok", "stderr": ""}
    assert _read(ok, "ceph x", check) == ""
    other = {"rc": 0, "stdout": "no", "stderr": ""}
    assert _read(other, "ceph x", check) == "ceph x did not print ok."
    # A command that failed is described by _failure; check is not asked.
    k = key()
    failed = {"rc": 2, "stdout": "ok", "stderr": "Error %s\n" % k}
    assert _read(failed, "ceph x", check) == "ceph x failed (rc 2): Error <key>."
    assert _read(dict(failed, stderr=""), "ceph x", check) == "ceph x failed (rc 2)."
    # Its result is checked as _cmd does.
    with pytest.raises(AnsibleFilterError) as err:
        _read({"skipped": True}, "ceph x", check)
    assert str(err.value) == "ceph x: the command was skipped"


@pytest.mark.parametrize(
    "stdout, reason",
    [
        ("01234567-89ab-cdef-0123-456789abcdef\n", ""),
        ("", "did not print an fsid"),
        ("01234567-89AB-CDEF-0123-456789ABCDEF", "did not print an fsid"),
    ],
)
def test_fsid(stdout, reason):
    assert _fsid(stdout) == reason


@pytest.mark.parametrize(
    "stdout, reason",
    [
        ("[client.a]\n\tkey = x\n", ""),
        ("[client.b]\n", "did not return the keyring of the entity"),
        ("", "did not return the keyring of the entity"),
        (" [client.a]\n", "did not return the keyring of the entity"),
    ],
)
def test_keyring_of(stdout, reason):
    assert _keyring_of("client.a")(stdout) == reason


def test_loop_failures():
    ok = {"item": {"daemon": "crash.a"}, "rc": 0, "stdout": "x", "stderr": ""}
    bad = {"item": {"daemon": "rgw.b"}, "rc": 1, "stdout": "", "stderr": "no"}
    worse = {"item": {"daemon": "rgw.c"}, "rc": 3, "stdout": "", "stderr": None}
    reg = {"results": [ok, bad, worse]}
    assert _loop_failures(reg, "redeploy", lambda i: i["daemon"]) == (
        "redeploy rgw.b failed (rc 1): no. redeploy rgw.c failed (rc 3)."
    )
    assert _loop_failures({"results": [ok]}, "redeploy", lambda i: i) == ""
    with pytest.raises(AnsibleFilterError) as err:
        _loop_failures({}, "ceph auth get", lambda i: i)
    assert str(err.value) == "ceph auth get: the result has no results"


def test_check_fields():
    _check_fields({"a": 1, "b": "x", "c": None}, {"a": int, "b": str}, "w", "it")
    cases = [
        ({"b": "x"}, "w: it has no a"),
        ({"a": True, "b": "x"}, "w: a is not an int"),
        ({"a": 1}, "w: it has no b"),
        ({"a": 1, "b": 2}, "w: b is not a str"),
    ]
    for entry, message in cases:
        with pytest.raises(AnsibleFilterError) as err:
            _check_fields(entry, {"a": int, "b": str}, "w", "it")
        assert str(err.value) == message
    assert _a(int) == "an int"
    assert _a((str, type(None))) == "a str or NoneType"


def test_osd_map():
    def dump(text):
        return {"rc": 0, "stdout": text, "stderr": ""}

    entries = [{"osd": 0, "up": 1}, {"osd": 1, "up": 0, "uuid": "u"}]
    text = json.dumps({"osds": entries, "epoch": 3})
    assert _osd_map(dump(text), {"osd": int}) == entries
    assert _osd_map(dump('{"osds": []}'), {"osd": int}) == []
    cases = [
        ("", "ceph osd dump: did not print JSON"),
        ("[]", "ceph osd dump: did not print a JSON object"),
        ("{}", "ceph osd dump: the object has no osds"),
        ('{"osds": [1]}', "ceph osd dump: an entry of osds is not an object"),
        ('{"osds": [{}]}', "ceph osd dump: an entry of osds has no osd"),
        ('{"osds": [{"osd": "0"}]}', "ceph osd dump: osd is not an int"),
    ]
    for text, message in cases:
        with pytest.raises(AnsibleFilterError) as err:
            _osd_map(dump(text), {"osd": int})
        assert str(err.value) == message
    with pytest.raises(AnsibleFilterError) as err:
        _osd_map({"rc": 0}, {})
    assert str(err.value) == "ceph osd dump: the result has no stdout"


def test_guarded_wraps_value_errors():
    k = key()

    @_guarded("cephx_example")
    def example(value):
        return int(value)

    assert example("12") == 12
    assert example.__name__ == "example"
    with pytest.raises(AnsibleFilterError) as err:
        example("x" + k)
    assert str(err.value) == "cephx_example: unexpected input (ValueError)"
    assert k not in str(err.value)
    assert k not in repr(err.value)
    assert err.value.__cause__ is None
    assert err.value.__context__ is None
    assert err.value.__suppress_context__ is True
    assert getattr(err.value, "orig_exc", None) is None
    with pytest.raises(AnsibleFilterError) as err:
        example(None)
    assert str(err.value) == "cephx_example: unexpected input (TypeError)"


def test_guarded_keeps_filter_errors():
    own = AnsibleFilterError("ceph fsid: did not print JSON")

    @_guarded("cephx_example")
    def example():
        raise own

    with pytest.raises(AnsibleFilterError) as err:
        example()
    assert err.value is own


def test_every_filter_is_guarded():
    import sys

    import cephx_lockbox
    import cephx_redeploy
    import cephx_rotate
    import cephx_rotate_texts
    import cephx_validate

    common = sys.modules["_cephx_common"]
    for plugin in (
        common,
        cephx_lockbox,
        cephx_redeploy,
        cephx_rotate,
        cephx_rotate_texts,
        cephx_validate,
    ):
        for name, f in plugin.FilterModule().filters().items():
            assert f.__wrapped__ is getattr(plugin, name)
            assert f.__name__ == name
            # Called without its arguments: the guard names the filter.
            with pytest.raises(AnsibleFilterError) as err:
                f()
            assert str(err.value) == name + ": unexpected input (TypeError)"
