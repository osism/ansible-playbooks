import json

import pytest
from ansible.errors import AnsibleFilterError

from cephx_redeploy import (
    FilterModule,
    cephx_redeploy_pending,
    cephx_redeploy_plan,
    cephx_redeploy_read_refusal,
    cephx_redeploy_refusal,
    cephx_redeploy_result,
    cephx_redeploy_stale,
    cephx_redeploy_up,
    cephx_redeploy_up_daemons,
    cephx_rotate_group_done,
)


def test_filters_registered():
    assert set(FilterModule().filters()) == {
        "cephx_redeploy_read_refusal",
        "cephx_redeploy_pending",
        "cephx_redeploy_stale",
        "cephx_redeploy_plan",
        "cephx_redeploy_result",
        "cephx_redeploy_refusal",
        "cephx_redeploy_up",
        "cephx_redeploy_up_daemons",
        "cephx_rotate_group_done",
    }


def guarded(name):
    return FilterModule().filters()[name]


# The reads before the redeploys

FSID = "4b5c8c0a-ff60-454b-a1b4-9747aa737d19"
KEY = "AQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
KEY_IN_STDERR = "Error EINVAL: bad key %s\n" % KEY


def cmd(rc=0, stdout="", stderr="", **more):
    return dict({"rc": rc, "stdout": stdout, "stderr": stderr}, **more)


@pytest.mark.parametrize("stdout", [FSID, FSID + "\n", "  %s  " % FSID])
def test_read_fsid(stdout):
    assert cephx_redeploy_read_refusal("fsid", cmd(stdout=stdout)) == ""


@pytest.mark.parametrize(
    "result, text",
    [
        (
            cmd(1, stderr=KEY_IN_STDERR),
            "ceph fsid failed (rc 1): Error EINVAL: bad key <key>.",
        ),
        (cmd(2), "ceph fsid failed (rc 2)."),
        (cmd(2, stderr=None), "ceph fsid failed (rc 2)."),
        (cmd(2, stderr=" \n"), "ceph fsid failed (rc 2)."),
        (cmd(stdout=""), "ceph fsid did not print an fsid."),
        (cmd(stdout=FSID.upper()), "ceph fsid did not print an fsid."),
        (cmd(stdout=FSID + "x"), "ceph fsid did not print an fsid."),
    ],
)
def test_read_fsid_refused(result, text):
    assert cephx_redeploy_read_refusal("fsid", result) == text


def auth_get(item, rc=0, first=None, stderr=""):
    stdout = "" if first is None else first + "\n\tkey = <never>\n"
    return cmd(rc, stdout=stdout if rc == 0 else "", stderr=stderr, item=item)


def test_read_auth_get():
    ok = auth_get("client.crash.a", first="[client.crash.a]")
    assert cephx_redeploy_read_refusal("auth_get", {"results": [ok]}) == ""
    assert cephx_redeploy_read_refusal("auth_get", {"results": []}) == ""
    reg = {
        "results": [
            ok,
            auth_get("client.crash.b", rc=2, stderr=KEY_IN_STDERR),
            auth_get("client.crash.c", first="[client.crash.x]"),
            auth_get("client.crash.d"),
            auth_get("client.crash.e", rc=1),
        ]
    }
    assert cephx_redeploy_read_refusal("auth_get", reg) == (
        "ceph auth get client.crash.b failed (rc 2): Error EINVAL: bad key"
        " <key>. ceph auth get client.crash.c did not return the keyring of"
        " the entity. ceph auth get client.crash.d did not return the keyring"
        " of the entity. ceph auth get client.crash.e failed (rc 1)."
    )


def test_read_orch_ps():
    ok = cmd(stdout=' [{"daemon_name": "crash.a"}]', item="crash")
    assert cephx_redeploy_read_refusal("orch_ps", {"results": [ok]}) == ""
    reg = {
        "results": [
            cmd(22, stderr=KEY_IN_STDERR, item="crash"),
            ok,
            cmd(stdout="[not json", item="rgw"),
            cmd(stdout="", item="rgw"),
        ]
    }
    assert cephx_redeploy_read_refusal("orch_ps", reg) == (
        "ceph orch ps --daemon-type crash failed (rc 22): Error EINVAL: bad key"
        " <key>. ceph orch ps --daemon-type rgw did not print JSON. ceph orch"
        " ps --daemon-type rgw did not print JSON."
    )


@pytest.mark.parametrize(
    "stdout, message",
    [
        ("{}", "did not print a JSON list"),
        ('{"daemon_name": "crash.a"}', "did not print a JSON list"),
        ('"crash.a"', "did not print a JSON list"),
        ('["crash.a"]', "an entry is not an object"),
        ('[{"x": 1}]', "an entry has no daemon_name"),
        ('[{"daemon_name": 5}]', "daemon_name is not a str"),
    ],
)
def test_read_orch_ps_wrong_shape_stops(stdout, message):
    # The kick's answer is judged as the waits judge theirs: JSON of
    # another shape stops at the read, before the wait.
    reg = {"results": [cmd(stdout=stdout, item="crash")]}
    with pytest.raises(AnsibleFilterError) as e:
        cephx_redeploy_read_refusal("orch_ps", reg)
    assert str(e.value) == "ceph orch ps --daemon-type crash: " + message


@pytest.mark.parametrize(
    "name, result",
    [
        ("fsid", {}),
        ("fsid", {"rc": 0}),
        ("fsid", {"rc": 2}),
        ("fsid", {"rc": "0", "stdout": FSID}),
        ("fsid", "x"),
        ("fsid", {"skipped": True}),
        ("auth_get", {}),
        ("auth_get", {"results": [{"item": "client.a"}]}),
        ("auth_get", {"results": [{"item": "client.a", "rc": 0}]}),
        ("auth_get", {"results": [cmd(stdout="[client.a]")]}),
        ("auth_get", {"results": [cmd(item="a", stdout=["[a]"])]}),
        ("orch_ps", {}),
        ("orch_ps", {"results": [{"item": "crash", "rc": 0}]}),
        ("orch_ps", {"results": [cmd(1)]}),
    ],
)
def test_read_unexpected_results_fail_closed(name, result):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_redeploy_read_refusal(name, result)
    assert "AQB" not in str(e.value)


def test_read_unknown():
    with pytest.raises(AnsibleFilterError):
        cephx_redeploy_read_refusal("nope", {})


# The redeploys (_redeploy-daemons.yml)

FP = "SHA256:fingerprint-of-the-key"
WRITTEN = 1763632800.0  # 2025-11-20T10:00:00Z
AFTER = "2025-11-20T10:00:00.000001Z"
BEFORE = "2025-11-20T09:59:00.000000Z"
AT = "2025-11-20T10:00:00.000000Z"
D0 = {"daemon": "crash.node-0", "entity": "client.crash.node-0", "host": "node-0"}
DEL = object()


def ps_entry(name="crash.node-0", **over):
    e = {
        "daemon_name": name,
        "status_desc": "running",
        "container_id": "c0",
        "started": AFTER,
    }
    e.update(over)
    return {k: v for k, v in e.items() if v is not DEL}


def redeploy(entries=None, stat=None, file_key=None, mon_key=None, daemons=(D0,)):
    entries = [ps_entry()] if entries is None else entries
    stat = {"exists": True, "mtime": WRITTEN} if stat is None else stat
    file_key = {"in_force_fp": FP} if file_key is None else file_key
    mon_key = {"in_force_fp": FP} if mon_key is None else mon_key
    ps = {"results": [cmd(stdout=json.dumps(entries), item="crash")]}
    files = {"results": [{"item": d, "stat": stat} for d in daemons]}
    keys = {"results": [dict(file_key, item=d) for d in daemons]}
    mons = {"results": [dict(mon_key, item=d["entity"]) for d in daemons]}
    return cephx_redeploy_plan(list(daemons), ps, files, keys, mons)


def why(**kw):
    return [p["why"] for p in redeploy(**kw)]


def test_redeploy_plan_keeps_a_daemon_with_the_key():
    assert redeploy() == [dict(D0, container_id="c0", why="")]


def test_redeploy_why_no_keyring_file():
    skipped = {"skipped": True, "changed": False}
    assert why(stat={"exists": False}, file_key=skipped) == [
        "no keyring file on its host"
    ]


@pytest.mark.parametrize(
    "file_key",
    [
        # The corrupt keyring: the inspection failed, failed_when: false
        # cleared `failed`, and the result has no fingerprint.
        {"failed": False, "changed": False, "msg": "cannot parse the keyring"},
        {"failed": True, "changed": False, "msg": "cannot read"},
        # A failed module result cannot be read, whatever it carries.
        {"failed": True, "in_force_fp": FP},
        {"failed": False, "in_force_fp": None},
        {"failed": False, "in_force_fp": ""},
        {"failed": False, "in_force_fp": 5},
    ],
)
def test_keyring_without_fingerprint_redeploys(file_key):
    assert why(file_key=file_key) == ["its keyring on the host cannot be read"]


def test_redeploy_why_keyring_differs():
    assert why(file_key={"in_force_fp": "SHA256:other"}) == [
        "its keyring on the host differs from the monitors' key"
    ]


def test_null_fingerprints_differ():
    # Q-D4: a missing fingerprint never matches another missing one. The
    # daemon's is "cannot be read"; the monitors' stops the play.
    assert why(file_key={"in_force_fp": None}) == [
        "its keyring on the host cannot be read"
    ]
    for mon_key in ({"in_force_fp": None}, {"in_force_fp": ""}, {"x": 1}):
        for file_key in ({"in_force_fp": None}, {"in_force_fp": FP}):
            with pytest.raises(AnsibleFilterError, match="client.crash.node-0"):
                redeploy(file_key=file_key, mon_key=mon_key)


def test_monitors_key_checked_without_keyring_file():
    # The monitors' fingerprint is checked for every daemon, also where no
    # comparison follows.
    with pytest.raises(AnsibleFilterError):
        redeploy(stat={"exists": False}, mon_key={"x": 1})


@pytest.mark.parametrize(
    "entries, text",
    [
        ([ps_entry(status_desc="stopped")], "not running (stopped)"),
        ([ps_entry(status_desc="error")], "not running (error)"),
        ([ps_entry(status_desc=None)], "not running (no status)"),
        ([ps_entry(status_desc="")], "not running (no status)"),
        ([ps_entry(status_desc=DEL)], "not running (no status)"),
        ([], "not running (not listed)"),
        ([ps_entry("crash.node-1")], "not running (not listed)"),
    ],
)
def test_redeploy_why_not_running(entries, text):
    assert why(entries=entries) == [text]


@pytest.mark.parametrize("started", [BEFORE, AT, None, "", DEL])
def test_redeploy_why_started_before_the_keyring(started):
    # An unknown start time (Q-D7) is the safe side: redeployed.
    assert why(entries=[ps_entry(started=started)]) == [
        "its container started before the keyring was written"
    ]


def test_redeploy_mtime_as_int():
    assert why(stat={"exists": True, "mtime": int(WRITTEN)}) == [""]


def test_redeploy_why_order():
    # Each reason applies only when those before it do not.
    assert why(
        stat={"exists": False}, file_key={}, entries=[ps_entry(status_desc="x")]
    ) == ["no keyring file on its host"]
    assert why(file_key={}, entries=[ps_entry(status_desc="x")]) == [
        "its keyring on the host cannot be read"
    ]
    assert why(
        file_key={"in_force_fp": "SHA256:other"},
        entries=[ps_entry(status_desc="x", started=BEFORE)],
    ) == ["its keyring on the host differs from the monitors' key"]
    assert why(entries=[ps_entry(status_desc="x", started=BEFORE)]) == [
        "not running (x)"
    ]


def test_redeploy_plan_container_id():
    for cid in (None, "", DEL):
        assert redeploy(entries=[ps_entry(container_id=cid)])[0]["container_id"] == ""
    plan = redeploy(entries=[ps_entry(container_id=DEL, status_desc="stopped")])
    assert plan[0]["container_id"] == ""
    assert redeploy(entries=[])[0]["container_id"] == ""


def test_redeploy_plan_several_types():
    daemons = (D0, {"daemon": "rgw.x.y", "entity": "client.rgw.x.y", "host": "h"})
    ps = {
        "results": [
            cmd(stdout=json.dumps([ps_entry()]), item="crash"),
            cmd(stdout=json.dumps([ps_entry("rgw.x.y", started=BEFORE)]), item="rgw"),
        ]
    }
    files = {
        "results": [
            {"item": d, "stat": {"exists": True, "mtime": WRITTEN}} for d in daemons
        ]
    }
    keys = {"results": [{"item": d, "in_force_fp": FP} for d in daemons]}
    mons = {"results": [{"item": d["entity"], "in_force_fp": FP} for d in daemons]}
    plan = cephx_redeploy_plan(list(daemons), ps, files, keys, mons)
    assert [p["why"] for p in plan] == [
        "",
        "its container started before the keyring was written",
    ]
    # A daemon type without its result stops.
    ps["results"].pop()
    with pytest.raises(AnsibleFilterError, match="--daemon-type rgw: no result"):
        cephx_redeploy_plan(list(daemons), ps, files, keys, mons)


@pytest.mark.parametrize(
    "kw",
    [
        # the monitors' fingerprint is missing
        {"mon_key": {"x": 1}},
        # no mtime, no exists, of the wrong type (Q-D5)
        {"stat": {"exists": True}},
        {"stat": {}},
        {"stat": {"exists": "yes", "mtime": WRITTEN}},
        {"stat": {"exists": True, "mtime": "1763632800"}},
        {"stat": {"exists": True, "mtime": None}},
        {"stat": {"exists": True, "mtime": True}},
        # a start time in another format, even where it is not compared
        {"entries": [ps_entry(started="2025-11-20 10:00:00")]},
        {"entries": [ps_entry(started=5)]},
        {
            "entries": [ps_entry(started="2025-11-20 10:00:00")],
            "stat": {"exists": False},
        },
        # fields of the wrong type (Q-D8)
        {"entries": [ps_entry(container_id=0)]},
        {"entries": [ps_entry(container_id=5)]},
        {"entries": [ps_entry(status_desc=1)]},
        # entries of another shape
        {"entries": [{"x": 1}, ps_entry()]},
        {"entries": ["crash.node-0"]},
        {"entries": {"daemon_name": "crash.node-0"}},
        # the daemon listed twice
        {"entries": [ps_entry(), ps_entry(status_desc="stopped")]},
    ],
)
def test_redeploy_plan_unexpected_input_fails_closed(kw):
    with pytest.raises(AnsibleFilterError):
        redeploy(**kw)


def test_redeploy_plan_keyring_inspection_not_run_fails_closed():
    # The keyring file exists, but its inspection was skipped or its host
    # unreachable: not a result to judge.
    for file_key in ({"skipped": True}, {"unreachable": True}):
        with pytest.raises(AnsibleFilterError):
            redeploy(file_key=file_key)


def test_redeploy_result():
    plan = [
        dict(D0, container_id="c0", why=""),
        dict(D0, daemon="crash.node-1", container_id="", why="not running (x)"),
    ]
    assert cephx_redeploy_result(plan) == [
        {"daemon": "crash.node-0", "entity": "client.crash.node-0", "action": "kept"},
        {
            "daemon": "crash.node-1",
            "entity": "client.crash.node-0",
            "action": "redeployed",
        },
    ]
    assert cephx_redeploy_result([]) == []
    with pytest.raises(AnsibleFilterError, match=r"unexpected input \(KeyError\)"):
        guarded("cephx_redeploy_result")([{"daemon": "a", "entity": "client.a"}])


# The wait for cephadm's refreshed list (_redeploy-daemons.yml)


def refreshed(*rows):
    return json.dumps(
        [
            {"daemon_name": n} if t is None else {"daemon_name": n, "last_refresh": t}
            for n, t in rows
        ]
    )


T0 = "2025-11-20T10:00:00.000000Z"
T1 = "2025-11-20T10:01:00.000000Z"
T2 = "2025-11-20T10:02:00.000000Z"
WAIT_DAEMONS = [
    {"daemon": "crash.a", "host": "h", "entity": "client.crash.a"},
    {"daemon": "crash.b", "host": "g", "entity": "client.crash.b"},
    {"daemon": "rgw.x", "host": "h", "entity": "client.rgw.x"},
]
CRASH = WAIT_DAEMONS[:2]
KICK = {
    "results": [
        cmd(stdout=refreshed(("crash.a", T0), ("crash.b", T1)), item="crash"),
        cmd(stdout=refreshed(("rgw.x", T0)), item="rgw"),
    ]
}


def poll(stdout, rc=0, item=None):
    r = cmd(rc, stdout=stdout, attempts=1)
    if item is not None:
        r["item"] = item
    return r


def wait(crash, rgw, crash_rc=0):
    return {"results": [poll(crash, crash_rc, "crash"), poll(rgw, item="rgw")]}


def pending(stdout, daemon_type="crash", daemons=WAIT_DAEMONS, kick=KICK, rc=0):
    return cephx_redeploy_pending(poll(stdout, rc), daemon_type, daemons, kick)


def test_redeploy_pending_and_stale():
    # Fresh: refreshed after the newest refresh the kick showed (T1).
    crash = refreshed(("crash.a", T2), ("crash.b", T2))
    ok = wait(crash, refreshed(("rgw.x", T1)))
    assert cephx_redeploy_stale(ok, WAIT_DAEMONS, KICK) == []
    assert pending(crash) == []
    # crash.a at T1 is not newer than crash.b's T1 in the kick; rgw.x missing
    crash = refreshed(("crash.a", T1), ("crash.b", T2))
    p = wait(crash, "[]")
    assert cephx_redeploy_stale(p, WAIT_DAEMONS, KICK) == ["crash.a", "rgw.x"]
    assert pending(crash) == ["crash.a"]
    assert pending("[]", "rgw") == ["rgw.x"]


def test_pending_takes_one_type():
    # Two types in the run: one poll of crash is judged without rgw's
    # result, and names only the daemons of its type.
    assert pending(refreshed(("crash.a", T0), ("crash.b", T2))) == ["crash.a"]
    assert pending(refreshed(("rgw.x", T0)), "rgw") == ["rgw.x"]
    assert pending(refreshed(("rgw.x", T1)), "rgw") == []


@pytest.mark.parametrize(
    "stdout, rc",
    [("", 1), ('[{"daemon_name": "crash.a"}]', 1), ("nope", 0), ("", 0), ("[", 0)],
)
def test_redeploy_pending_command_failed_or_not_json_is_not_yet(stdout, rc):
    # Within the bounded wait: not yet, for every daemon of the type.
    assert pending(stdout, rc=rc) == ["crash.a", "crash.b"]
    assert cephx_redeploy_stale(wait(stdout, "[]", rc), CRASH, KICK) == [
        "crash.a",
        "crash.b",
    ]


def test_command_rc_decides():
    # failed_when: false clears `failed`; the rc decides.
    rc1 = dict(poll(refreshed(("crash.a", T2), ("crash.b", T2)), 1), failed=False)
    assert cephx_redeploy_pending(rc1, "crash", CRASH, KICK) == ["crash.a", "crash.b"]
    rc0 = dict(poll(refreshed(("crash.a", T2), ("crash.b", T2))), failed=True)
    assert cephx_redeploy_pending(rc0, "crash", CRASH, KICK) == []
    up_rc1 = dict(cmd(1, stdout=json.dumps([up_entry("c2")])), failed=False)
    assert cephx_redeploy_up(up_rc1, UP_ITEM) is False
    fsid_rc1 = cmd(1, stdout=FSID, stderr="Error", failed=False)
    assert cephx_redeploy_read_refusal("fsid", fsid_rc1) == (
        "ceph fsid failed (rc 1): Error."
    )
    redeploy_rc1 = dict(cmd(1, item={"daemon": "crash.a"}), failed=False)
    assert cephx_redeploy_refusal({"results": [redeploy_rc1]}) == (
        "ceph orch daemon redeploy crash.a failed (rc 1)."
    )


def test_redeploy_pending_without_last_refresh():
    # Never refreshed: not yet.
    stdout = refreshed(("crash.a", None), ("crash.b", T2))
    assert pending(stdout) == ["crash.a"]
    assert cephx_redeploy_stale(wait(stdout, "[]"), CRASH, KICK) == ["crash.a"]


def test_redeploy_kick_without_refresh_times():
    # Nothing refreshed in the kick's answer: any refresh is after it.
    kick = {"results": [cmd(stdout=refreshed(("crash.a", None)), item="crash")]}
    assert pending(refreshed(("crash.a", T0), ("crash.b", T0)), kick=kick) == []
    kick = {"results": [cmd(stdout="[]", item="crash")]}
    assert pending(refreshed(("crash.a", T0), ("crash.b", None)), kick=kick) == [
        "crash.b"
    ]


def test_missing_daemon_is_not_yet():
    # A daemon being redeployed can vanish from cephadm's list for a
    # moment: missing in one poll, back in the next.
    first = refreshed(("crash.b", T2))
    second = refreshed(("crash.a", T2), ("crash.b", T2))
    assert pending(first) == ["crash.a"]
    assert pending(second) == []
    assert cephx_redeploy_stale(wait(first, "[]"), CRASH, KICK) == ["crash.a"]
    assert cephx_redeploy_stale(wait(second, "[]"), CRASH, KICK) == []
    # The same for the new container.
    assert cephx_redeploy_up(cmd(stdout="[]"), UP_ITEM) is False
    other = json.dumps([up_entry("c2", name="crash.b")])
    assert cephx_redeploy_up(cmd(stdout=other), UP_ITEM) is False
    back = json.dumps([up_entry("c2")])
    assert cephx_redeploy_up(cmd(stdout=back), UP_ITEM) is True


def test_missing_daemon_type_stops():
    # rgw.x is asked for, but the loop has no result for rgw.
    only_crash = {"results": [poll(refreshed(("crash.a", T2)), item="crash")]}
    with pytest.raises(AnsibleFilterError, match="--daemon-type rgw: no result"):
        cephx_redeploy_stale(only_crash, WAIT_DAEMONS, KICK)
    # Nor may the kick lack it: the poll ends the wait, the check after
    # the loop stops.
    kick = {"results": KICK["results"][:1]}
    assert pending(refreshed(("rgw.x", T2)), "rgw", kick=kick) == []
    p = wait(refreshed(("crash.a", T2), ("crash.b", T2)), refreshed(("rgw.x", T2)))
    with pytest.raises(AnsibleFilterError, match="--daemon-type rgw: no result"):
        cephx_redeploy_stale(p, WAIT_DAEMONS, kick)
    # Nor a type have two results.
    twice = wait(refreshed(("crash.a", T2)), "[]")
    twice["results"].append(poll("[]", item="rgw"))
    with pytest.raises(AnsibleFilterError, match="--daemon-type rgw: two results"):
        cephx_redeploy_stale(twice, WAIT_DAEMONS, KICK)


def test_no_daemons_of_the_type_stops():
    import cephx_redeploy

    assert pending("[]", "mds") == []
    with pytest.raises(AnsibleFilterError, match="no daemons of the type"):
        cephx_redeploy._pending(poll("[]"), "mds", WAIT_DAEMONS, KICK)


@pytest.mark.parametrize(
    "rows",
    [
        [("crash.a", T2), ("crash.a", T0)],  # fresh, then stale
        [("crash.a", T0), ("crash.a", T2)],  # stale, then fresh
        [("crash.a", T2), ("crash.a", T2)],
    ],
)
def test_duplicate_daemon_row_stops(rows):
    stdout = refreshed(*rows, ("crash.b", T2))
    message = "ceph orch ps --daemon-type crash: crash.a is listed twice"
    # The poll ends the wait (its task is no_log, a stop there would be
    # censored); the check after the loop stops, naming the daemon.
    assert pending(stdout) == []
    with pytest.raises(AnsibleFilterError) as e:
        cephx_redeploy_stale(wait(stdout, "[]"), CRASH, KICK)
    assert str(e.value) == message
    # In the kick's answer too.
    kick = {"results": [cmd(stdout=refreshed(*rows), item="crash")]}
    fine = refreshed(("crash.a", T2), ("crash.b", T2))
    assert pending(fine, kick=kick) == []
    with pytest.raises(AnsibleFilterError) as e:
        cephx_redeploy_stale(wait(fine, "[]"), CRASH, kick)
    assert str(e.value) == message


def test_duplicate_row_of_another_daemon_is_not_ours():
    # Only the daemons asked for are judged.
    stdout = refreshed(("crash.z", T0), ("crash.z", T0), ("crash.a", T2))
    assert pending(stdout, daemons=WAIT_DAEMONS[:1]) == []


def test_last_refresh_compared_as_times():
    # Q-D1: 10:00:00.51 is after 10:00:00.5, though "1" sorts before "Z"
    # as text; and the same time written with another number of digits
    # is not after it.
    kick = {
        "results": [
            cmd(stdout=refreshed(("crash.a", "2025-11-20T10:00:00.5Z")), item="crash")
        ]
    }
    one = WAIT_DAEMONS[:1]
    newer = refreshed(("crash.a", "2025-11-20T10:00:00.51Z"))
    assert pending(newer, daemons=one, kick=kick) == []
    same = refreshed(("crash.a", "2025-11-20T10:00:00.500000Z"))
    assert pending(same, daemons=one, kick=kick) == ["crash.a"]
    # Case means nothing to a time: text that is not one ends the wait,
    # and the check after it stops.
    for text in ("a", "Z", "2025-11-20 10:00:00"):
        stdout = refreshed(("crash.a", text))
        assert pending(stdout, daemons=one, kick=kick) == []
        with pytest.raises(AnsibleFilterError) as e:
            cephx_redeploy_stale(wait_crash(stdout), one, kick)
        assert str(e.value) == (
            "ceph orch ps --daemon-type crash: a last_refresh is not a time"
        )


def wait_crash(stdout):
    return {"results": [poll(stdout, item="crash")]}


@pytest.mark.parametrize(
    "stdout",
    [
        json.dumps([{"daemon_name": "crash.a", "last_refresh": None}]),
        json.dumps([{"daemon_name": "crash.a", "last_refresh": 5}]),
        json.dumps([{"daemon_name": "crash.a", "last_refresh": "a"}]),
        json.dumps(["crash.a"]),
        json.dumps([{"x": 1}]),
        json.dumps([{"daemon_name": 5}]),
        json.dumps({"daemon_name": "crash.a", "last_refresh": T2}),
        json.dumps("crash.a"),
    ],
)
def test_redeploy_wait_wrong_shape_stops(stdout):
    # The poll ends the wait; the check after the loop stops.
    assert pending(stdout, daemons=WAIT_DAEMONS[:1]) == []
    with pytest.raises(AnsibleFilterError) as e:
        cephx_redeploy_stale(wait(stdout, "[]"), WAIT_DAEMONS, KICK)
    assert str(e.value).startswith("ceph orch ps --daemon-type crash: ")


@pytest.mark.parametrize(
    "result",
    [
        {"stdout": "[]"},
        {"rc": "0", "stdout": "[]"},
        {"rc": 0, "stdout": None},
        {"rc": 0, "stdout": "[]", "skipped": True},
        "x",
    ],
)
def test_redeploy_pending_unexpected_result_fails_closed(result):
    assert cephx_redeploy_pending(result, "crash", CRASH, KICK) == []
    if isinstance(result, dict):
        with pytest.raises(AnsibleFilterError):
            cephx_redeploy_stale({"results": [dict(result, item="crash")]}, CRASH, KICK)


# The redeploy and the new container (_redeploy-daemons-batch.yml)


def test_redeploy_refusal():
    reg = {
        "results": [
            cmd(22, stderr=KEY_IN_STDERR, item={"daemon": "crash.a"}),
            cmd(item={"daemon": "crash.b"}),
            cmd(1, item={"daemon": "crash.c"}),
        ]
    }
    assert cephx_redeploy_refusal(reg) == (
        "ceph orch daemon redeploy crash.a failed (rc 22): Error EINVAL: bad key"
        " <key>. ceph orch daemon redeploy crash.c failed (rc 1)."
    )
    assert cephx_redeploy_refusal({"results": [cmd(item={"daemon": "a"})]}) == ""
    with pytest.raises(AnsibleFilterError):
        cephx_redeploy_refusal({"results": [{"item": {"daemon": "a"}}]})


UP_ITEM = {"daemon": "crash.a", "container_id": "c1"}


def up_entry(cid, name="crash.a", **over):
    return ps_entry(name, container_id=cid, **over)


def up(cid_before, *entries, rc=0, stdout=None):
    item = {"daemon": "crash.a", "container_id": cid_before}
    out = json.dumps(list(entries)) if stdout is None else stdout
    return cmd(rc, stdout=out), item


@pytest.mark.parametrize(
    "case, expected",
    [
        (up("c1", up_entry("c2")), True),
        (up("", up_entry("c2")), True),
        (up("c1", up_entry("c1")), False),
        (up("", up_entry("")), False),
        (up("c1", up_entry(None)), False),
        (up("c1", up_entry(DEL)), False),
        (up("c1", up_entry("c2", status_desc="starting")), False),
        (up("c1", up_entry("c2", status_desc=DEL)), False),
        (up("c1", up_entry("c2", status_desc=None)), False),
        (up("c1", up_entry("c2", name="crash.b")), False),
        (up("c1"), False),
        (up("c1", rc=1, stdout=""), False),
        (up("c1", stdout="not json"), False),
        (up("c1", stdout="[not json"), False),
        (up("c1", stdout=" " + json.dumps([up_entry("c2")])), True),
    ],
)
def test_redeploy_up(case, expected):
    result, item = case
    assert cephx_redeploy_up(result, item) is expected
    reg = {"results": [dict(result, item=item)]}
    assert cephx_redeploy_up_daemons(reg) == (["crash.a"] if expected else [])


@pytest.mark.parametrize(
    "case",
    [
        up("c1", {"x": 1}, up_entry("c2")),
        up("c1", "crash.a"),
        up("c1", stdout='{"daemon_name": "crash.a"}'),
        up("c1", up_entry(5)),
        up("c1", up_entry("c2", status_desc=1)),
        # Q-D2: the daemon listed twice, a new container first or last
        up("c1", up_entry("c1"), up_entry("c3")),
        up("c1", up_entry("c3"), up_entry("c1")),
        ({"stdout": "[]"}, {"daemon": "crash.a", "container_id": "c1"}),
    ],
)
def test_redeploy_up_unexpected_output_fails_closed(case):
    # The poll ends the wait; the check after the loop stops.
    result, item = case
    assert cephx_redeploy_up(result, item) is True
    with pytest.raises(AnsibleFilterError):
        cephx_redeploy_up_daemons({"results": [dict(result, item=item)]})


def test_duplicate_daemon_row_stops_the_new_container_wait():
    result, item = up("c1", up_entry("c1"), up_entry("c3"))
    assert cephx_redeploy_up(result, item) is True
    with pytest.raises(AnsibleFilterError) as e:
        cephx_redeploy_up_daemons({"results": [dict(result, item=item)]})
    assert str(e.value) == "ceph orch ps --daemon-type crash: crash.a is listed twice"


def test_redeploy_up_daemons():
    reg = {
        "results": [
            dict(cmd(stdout=json.dumps([up_entry("c2")])), item=UP_ITEM),
            dict(
                cmd(stdout=json.dumps([up_entry("c2", name="crash.b")])),
                item={"daemon": "crash.b", "container_id": "c2"},
            ),
        ]
    }
    assert cephx_redeploy_up_daemons(reg) == ["crash.a"]
    for bad in ({}, {"results": "x"}, {"results": [cmd()]}):
        with pytest.raises(AnsibleFilterError):
            cephx_redeploy_up_daemons(bad)


# What was done for a group of rotated keys (_rotate-keys-rotate.yml)

GROUP = {
    "names": ["client.crash.a", "client.crash.b"],
    "class": "crash",
    "one_at_a_time": False,
    "daemons": WAIT_DAEMONS[:2],
}
SET_KEY = [
    {"name": "client.crash.a", "action": "rotated"},
    {"name": "client.crash.b", "action": "no new key"},
    {"name": "client.crash.a", "action": "no new key"},
]
REDEPLOYED = [
    {"daemon": "crash.a", "entity": "client.crash.a", "action": "redeployed"},
    {"daemon": "crash.b", "entity": "client.crash.b", "action": "kept"},
]


def done(name, action, redeployed=(), kept=(), cls="crash"):
    return {
        "name": name,
        "class": cls,
        "action": action,
        "checkout": [],
        "monitors": False,
        "redeployed": list(redeployed),
        "kept": list(kept),
    }


def test_rotate_group_done():
    # The last action of an entity counts.
    assert cephx_rotate_group_done(GROUP, REDEPLOYED, SET_KEY) == [
        done("client.crash.a", "no new key", redeployed=["crash.a"]),
        done("client.crash.b", "no new key", kept=["crash.b"]),
    ]


def test_rotate_group_done_without_daemons():
    group = {"names": ["client.bootstrap-osd"], "class": "bootstrap", "daemons": []}
    keys = [{"name": "client.bootstrap-osd", "action": "rotated"}]
    assert cephx_rotate_group_done(group, REDEPLOYED, keys) == [
        done("client.bootstrap-osd", "rotated", cls="bootstrap")
    ]


def test_rotate_group_done_without_action_fails_closed():
    with pytest.raises(AnsibleFilterError, match="client.crash.b"):
        cephx_rotate_group_done(GROUP, REDEPLOYED, SET_KEY[:1])
    with pytest.raises(AnsibleFilterError, match=r"unexpected input \(KeyError\)"):
        guarded("cephx_rotate_group_done")(
            GROUP, REDEPLOYED, [{"name": "client.crash.a"}]
        )
