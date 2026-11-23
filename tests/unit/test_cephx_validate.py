import base64
import calendar
import json
import os
import struct
import time

import pytest
from ansible.errors import AnsibleFilterError

from cephx_validate import (
    FilterModule,
    cephx_aes_allowed,
    cephx_auth_get_failed,
    cephx_check_checkout,
    cephx_check_guests,
    cephx_check_monitor,
    cephx_check_old,
    cephx_check_pending,
    cephx_compute_secrets,
    cephx_validator_lines,
    cephx_validator_tests,
)

SERVICES = {
    "client.admin": ["cephclient"],
    "client.cinder": ["cinder", "nova"],
    "client.glance": ["glance"],
    "client.nova": ["cinder", "nova"],
}
OPENSTACK_KEYS = [{"name": "client.glance"}, {"name": "client.foo"}]
REPO_STEP = (
    "staged, not committed yet: copy the keyring files of the checkout into the"
    " repository, commit, push, osism apply configuration, then "
)
OSD_FSID = "aaaaaaaa-0000-4000-8000-000000000000"
UN = "5a2bf0bf-e1ab-4a6a-bc32-404bb6ba91fd"
UC = "63dd366f-e403-41f2-beff-dad9980a1637"


def key(type_=2):
    """A random key of the given type (1: aes, 2: aes256k), never printed."""
    secret = os.urandom(16 * type_)
    header = struct.pack("<HIIH", type_, 1700000000, 0, len(secret))
    return base64.b64encode(header + secret).decode()


def flags(pending=False, aes=False):
    return {"pending": pending, "aes": aes}


def cmd(stdout="", rc=0, stderr="", **kw):
    """A command's registered result; failed_when: false clears failed."""
    return dict({"rc": rc, "stdout": stdout, "stderr": stderr, "failed": False}, **kw)


def test_filters_registered():
    filters = FilterModule().filters()
    for f in (
        cephx_check_pending,
        cephx_aes_allowed,
        cephx_check_old,
        cephx_check_monitor,
        cephx_check_checkout,
        cephx_compute_secrets,
        cephx_check_guests,
        cephx_validator_tests,
        cephx_validator_lines,
        cephx_auth_get_failed,
    ):
        assert filters[f.__name__].__wrapped__ is f


# --- check 1: pending keys


def osd_dump(*osds):
    return cmd(json.dumps({"epoch": 40, "osds": list(osds)}))


def notes(rows):
    return {r["entity"]: r["note"] for r in rows}


def test_pending_builtin_entity():
    rows = cephx_check_pending(
        {"client.glance": flags(pending=True), "client.nova": flags()},
        {"skipped": True},
        SERVICES,
        OPENSTACK_KEYS,
    )
    assert rows == [
        {
            "entity": "client.glance",
            "location": "cluster",
            "result": "pending",
            "note": REPO_STEP
            + "osism apply glance; the first use of the new key commits it",
        }
    ]


def test_pending_cinder_and_admin():
    n = notes(
        cephx_check_pending(
            {"client.cinder": flags(pending=True), "client.admin": flags(True)},
            {"skipped": True},
            SERVICES,
            [],
        )
    )
    assert n["client.cinder"] == (
        REPO_STEP + "osism apply cinder, then osism apply nova; then live-migrate"
        " every running guest; the first use of the new key commits it"
    )
    assert n["client.admin"] == (
        REPO_STEP + "osism apply cephclient; the first use of the new key commits it"
    )


def test_pending_site_openstack_key():
    n = notes(
        cephx_check_pending(
            {"client.foo": flags(pending=True)},
            {"skipped": True},
            SERVICES,
            OPENSTACK_KEYS,
        )
    )
    assert n["client.foo"] == (
        REPO_STEP + "apply the services that use client.foo;"
        " the first use of the new key commits it"
    )


def test_pending_lockbox_names_the_osd():
    name = "client.osd-lockbox." + OSD_FSID
    n = notes(
        cephx_check_pending(
            {name: flags(pending=True)},
            osd_dump({"osd": 1, "uuid": "x"}, {"osd": 3, "uuid": OSD_FSID}),
            SERVICES,
            OPENSTACK_KEYS,
        )
    )
    assert n[name] == "staged lockbox key of osd.3: its next start commits it"


def test_pending_lockbox_without_osd():
    name = "client.osd-lockbox." + OSD_FSID
    for dump in (osd_dump({"osd": 1, "uuid": "x"}), osd_dump()):
        n = notes(cephx_check_pending({name: flags(True)}, dump, SERVICES, []))
        assert n[name] == (
            "staged lockbox key, but no OSD in the OSD map has the fsid it is named after"
        )


def test_pending_unknown_entity():
    n = notes(
        cephx_check_pending(
            {"client.crash.node-0": flags(pending=True)},
            {"skipped": True},
            SERVICES,
            [],
        )
    )
    assert n["client.crash.node-0"] == (
        "not staged by cephadm-rotate-keys: find out what uses this entity, then"
        " ceph auth commit-pending client.crash.node-0 or ceph auth clear-pending"
        " client.crash.node-0"
    )


def test_pending_order_and_skipped_osd_dump():
    # the osd dump result without stdout was skipped (no pending lockbox key)
    rows = cephx_check_pending(
        {
            "client.b": flags(pending=True),
            "client.a": flags(),
            "client.c": flags(pending=True),
        },
        {"skipped": True, "changed": False},
        {},
        [],
    )
    assert [r["entity"] for r in rows] == ["client.b", "client.c"]
    assert cephx_check_pending({}, {"skipped": True}, SERVICES, []) == []


OSD_DUMP_SHAPES = [
    ("{}", "ceph osd dump: the object has no osds"),
    ('{"osds": {}}', "ceph osd dump: osds is not a list"),
    ("[]", "ceph osd dump: did not print a JSON object"),
    ('{"osds": [1]}', "ceph osd dump: an entry of osds is not an object"),
    ('{"osds": [{"uuid": "x"}]}', "ceph osd dump: an entry of osds has no osd"),
    ('{"osds": [{"osd": 1}]}', "ceph osd dump: an entry of osds has no uuid"),
    ('{"osds": [{"osd": "1", "uuid": "x"}]}', "ceph osd dump: osd is not an int"),
    ('{"osds": [{"osd": true, "uuid": "x"}]}', "ceph osd dump: osd is not an int"),
    ('{"osds": [{"osd": 1, "uuid": 2}]}', "ceph osd dump: uuid is not a str"),
    # Two OSDs with one uuid: which one the lockbox key belongs to is not
    # known. The ids are named, never the uuid.
    (
        '{"osds": [{"osd": 1, "uuid": "u"}, {"osd": 3, "uuid": "v"},'
        ' {"osd": 2, "uuid": "u"}]}',
        "ceph osd dump: osd.1 and osd.2 have the same uuid",
    ),
]


@pytest.mark.parametrize("stdout,message", OSD_DUMP_SHAPES)
def test_pending_osd_dump_shape(stdout, message):
    # Q-V5: every entry of the OSD map is {osd: int, uuid: str}; anything
    # else stops, naming the command and field (never the value)
    with pytest.raises(AnsibleFilterError) as e:
        cephx_check_pending(
            {"client.osd-lockbox." + OSD_FSID: flags(True)},
            cmd(stdout),
            SERVICES,
            [],
        )
    assert str(e.value) == message


def test_pending_osd_dump_result_checked():
    k = key()
    name = {"client.osd-lockbox." + OSD_FSID: flags(True)}
    with pytest.raises(AnsibleFilterError) as e:
        cephx_check_pending(name, cmd(rc=2, stderr="bad " + k), SERVICES, [])
    assert str(e.value) == "ceph osd dump failed (rc 2): bad <key>."
    with pytest.raises(AnsibleFilterError) as e:
        cephx_check_pending(name, {"stdout": "{}"}, SERVICES, [])
    assert str(e.value) == "ceph osd dump: the result has no rc"


@pytest.mark.parametrize(
    "openstack_keys", [[{"key": "client.x"}], ["client.x"], [None], [{"name": 1}]]
)
def test_pending_openstack_keys_entry_without_name(openstack_keys):
    # openstack_keys is a site variable: an entry without a name stops,
    # naming the variable.
    with pytest.raises(AnsibleFilterError) as e:
        cephx_check_pending({}, {"skipped": True}, SERVICES, openstack_keys)
    assert str(e.value) == "openstack_keys: an entry has no name"


@pytest.mark.parametrize("openstack_keys", [None, "client.x", {"name": "client.x"}])
def test_pending_openstack_keys_not_a_list(openstack_keys):
    # openstack_keys: null (or any value that is not a list) stops, naming
    # the variable.
    with pytest.raises(AnsibleFilterError) as e:
        cephx_check_pending({}, {"skipped": True}, SERVICES, openstack_keys)
    assert str(e.value) == "openstack_keys is not a list"


# --- check 2: old key type


def test_old_rows():
    rows = cephx_check_old(
        {"client.a": flags(aes=True), "client.b": flags(), "osd.0": flags(True, True)}
    )
    assert rows == [
        {
            "entity": e,
            "location": "cluster",
            "result": "aes",
            "note": "its key in force is of the old type aes",
        }
        for e in ("client.a", "osd.0")
    ]


def monmap(*ciphers):
    m = {"epoch": 3, "mons": []}
    if ciphers:
        m["auth_allowed_ciphers"] = [{"name": n, "value": v} for n, v in ciphers]
    return json.dumps(m)


def test_aes_allowed():
    assert cephx_aes_allowed(monmap()) is True
    assert cephx_aes_allowed(monmap(("aes", 1), ("aes256k", 2))) is True
    assert cephx_aes_allowed(monmap(("aes256k", 2))) is False
    assert cephx_aes_allowed(json.dumps({"auth_allowed_ciphers": []})) is False


@pytest.mark.parametrize(
    "ciphers",
    [
        {"value": 1},
        [1],
        [{"name": "aes"}],
        [{"name": "aes", "value": "1"}],
        [{"name": "aes", "value": True}],
        [{"name": "aes", "value": None}],
    ],
)
def test_aes_allowed_ciphers_shape(ciphers):
    # Q-V4: auth_allowed_ciphers is a list of {value: int}; anything else
    # stops instead of reading as "excludes aes"
    with pytest.raises(AnsibleFilterError) as e:
        cephx_aes_allowed(json.dumps({"auth_allowed_ciphers": ciphers}))
    assert str(e.value) == "ceph mon dump: unexpected auth_allowed_ciphers"


# --- check 3: monitor copies


def mon_case(host, name, exists=True, unreachable=False, read=None):
    stat = {"item": [host, name]}
    if unreachable:
        stat["unreachable"] = True
    else:
        stat["stat"] = {"exists": exists}
    reads = []
    if read is not None:
        reads.append(dict(read, item=[host, name]))
    return stat, reads


def mon_rows(cases, fps):
    stats = [c[0] for c in cases]
    reads = [r for c in cases for r in c[1]]
    return cephx_check_monitor({"results": stats}, {"results": reads}, fps)


def test_monitor_results():
    fp = {"client.a": "fpa", "client.b": "fpb"}
    k = key()
    good = {"entity": "client.a", "has_pending": False, "key_fp": "fpa"}
    rows = mon_rows(
        [
            mon_case("m1", "client.a", read=good),
            mon_case("m1", "client.b", exists=False),
            mon_case("m2", "client.a", read={"failed": False, "msg": "bad " + k}),
            mon_case("m2", "client.b", read={"failed": True}),
            mon_case("m3", "client.a", read=dict(good, has_pending=True)),
            mon_case("m3", "client.b", read=dict(good, entity="client.b")),
            mon_case("m4", "client.b", read=good),
            mon_case("m5", "client.a", unreachable=True),
            mon_case("m6", "client.a", read={"unreachable": True}),
        ],
        fp,
    )
    assert [(r["entity"], r["location"], r["result"], r["note"]) for r in rows] == [
        ("client.a", "m1", "matches", "/etc/ceph/ceph.client.a.keyring"),
        (
            "client.b",
            "m1",
            "missing",
            "no such file: copy-ceph-keys reads the keyring from here and would skip it",
        ),
        ("client.a", "m2", "unreadable", "bad <key>"),
        ("client.b", "m2", "unreadable", "not read"),
        (
            "client.a",
            "m3",
            "differs",
            "carries a pending key line, which Ceph clients cannot read",
        ),
        ("client.b", "m3", "differs", "holds another key than the key in force next"),
        ("client.b", "m4", "differs", "the keyring of client.a"),
        ("client.a", "m5", "failed", "the host cannot be reached"),
        ("client.a", "m6", "failed", "the host cannot be reached"),
    ]
    assert k not in json.dumps(rows)


def test_monitor_stat_failed():
    # Q-V2: a stat that failed on a reachable host is "failed" with the
    # module's message, masked; not "missing"
    k = key()
    rows = cephx_check_monitor(
        {
            "results": [
                {"item": ["m1", "client.a"], "failed": True, "msg": "denied " + k},
                {"item": ["m2", "client.a"], "failed": True},
            ]
        },
        {"results": []},
        {},
    )
    assert rows == [
        row("client.a", "failed", "the stat failed: denied <key>", "m1"),
        row("client.a", "failed", "the stat failed", "m2"),
    ]


@pytest.mark.parametrize(
    "stat,message",
    [
        ({}, "stat of the monitor keyrings: the result has no stat"),
        ({"stat": None}, "stat of the monitor keyrings: the result has no stat"),
        ({"stat": {}}, "stat of the monitor keyrings: stat.exists is not a bool"),
        (
            {"stat": {"exists": "yes"}},
            "stat of the monitor keyrings: stat.exists is not a bool",
        ),
    ],
)
def test_monitor_stat_shape(stat, message):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_check_monitor(
            {"results": [dict(stat, item=["m1", "client.a"])]}, {"results": []}, {}
        )
    assert str(e.value) == message


MISSING_FP = [
    ({"entity": "client.a", "has_pending": False}, {}),
    ({"entity": "client.a", "has_pending": False, "key_fp": "fpa"}, {}),
    ({"entity": "client.a", "has_pending": False}, {"client.a": "fpa"}),
    ({"entity": "client.a", "has_pending": False, "key_fp": None}, {"client.a": "fp"}),
]


@pytest.mark.parametrize("read,fps", MISSING_FP)
def test_monitor_missing_fingerprint_fails(read, fps):
    # a fingerprint missing on either side stops the play, naming the
    # entity: never "matches"
    with pytest.raises(
        AnsibleFilterError, match="no fingerprint to compare for client.a"
    ):
        cephx_check_monitor(
            {"results": [{"item": ["m1", "client.a"], "stat": {"exists": True}}]},
            {"results": [dict(read, item=["m1", "client.a"])]},
            fps,
        )


@pytest.mark.parametrize("read,fps", MISSING_FP)
def test_checkout_missing_fingerprint_fails(read, fps):
    with pytest.raises(
        AnsibleFilterError, match="no fingerprint to compare for client.a"
    ):
        f = {"name": "client.a", "dest": "/c/a"}
        cephx_check_checkout(
            [f],
            {"results": [dict(read, item=f)]},
            {"results": [git(item=f)]},
            {"client.a": flags()},
            fps,
            "/c",
        )


def test_monitor_empty_results():
    # an empty loop has no rows; a loop result without results stops (Q-V1:
    # a check that saw nothing has not passed)
    empty = {"skipped": True, "results": [], "msg": "No items in the list"}
    assert cephx_check_monitor(empty, {"results": []}, {}) == []
    with pytest.raises(AnsibleFilterError) as e:
        cephx_check_monitor({}, {"results": []}, {})
    assert str(e.value) == "stat of the monitor keyrings: the result has no results"
    with pytest.raises(AnsibleFilterError) as e:
        cephx_check_monitor(empty, {}, {})
    assert str(e.value) == (
        "cephx_keyring of the monitor keyrings: the result has no results"
    )
    with pytest.raises(AnsibleFilterError) as e:
        cephx_check_monitor({"results": "x"}, {"results": []}, {})
    assert str(e.value) == "stat of the monitor keyrings: the results are not a list"


@pytest.mark.parametrize(
    "read,message",
    [
        ({"entity": 1}, "cephx_keyring: entity is not a str"),
        ({"entity": "client.a"}, "cephx_keyring: has_pending is not a bool"),
        (
            {"entity": "client.a", "has_pending": "no"},
            "cephx_keyring: has_pending is not a bool",
        ),
    ],
)
def test_monitor_read_shape(read, message):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_check_monitor(
            {"results": [{"item": ["m1", "client.a"], "stat": {"exists": True}}]},
            {"results": [dict(read, item=["m1", "client.a"])]},
            {"client.a": "fpa"},
        )
    assert str(e.value) == message


# --- check 4: checkout


def co_files(cases):
    return [{"name": n, "dest": "/c/" + n + ".keyring"} for n, _, _ in cases]


def co_rows(cases, cluster=None, fps=None):
    files = co_files(cases)
    reads = {"results": [dict(m, item=f) for f, (_, m, _) in zip(files, cases)]}
    gits = {"results": [dict(g, item=f) for f, (_, _, g) in zip(files, cases)]}
    if cluster is None:
        cluster = {n: flags() for n, _, _ in cases}
    if fps is None:
        fps = {n: "fp-" + n for n, _, _ in cases}
    return cephx_check_checkout(files, reads, gits, cluster, fps, "/c")


def ok_read(name, **kw):
    return dict({"entity": name, "has_pending": False, "key_fp": "fp-" + name}, **kw)


def git(stdout="", rc=0, **kw):
    return cmd(stdout, rc, **kw)


def test_checkout_results():
    k = key()
    rows = co_rows(
        [
            ("client.a", ok_read("client.a"), git()),
            ("client.b", {"failed": False, "msg": "x " + k}, git()),
            ("client.c", ok_read("client.a"), git()),
            ("client.d", ok_read("client.d", has_pending=True), git()),
            ("client.e", ok_read("client.e", key_fp="old"), git()),
            ("client.f", ok_read("client.f"), git(rc=128, stderr="fatal " + k)),
            ("client.g", ok_read("client.g"), git("?? /c/client.g.keyring\n")),
            ("client.h", ok_read("client.h"), git("!! /c/client.h.keyring\n")),
            ("client.i", ok_read("client.i"), git(" M /c/client.i.keyring\n")),
            ("client.j", ok_read("client.j"), git("A  /c/client.j.keyring\n")),
            ("client.k", ok_read("client.k"), git(rc=128)),
        ]
    )
    got = [(r["entity"], r["location"], r["result"], r["note"]) for r in rows]
    assert got == [
        ("client.a", "/c/client.a.keyring", "matches", ""),
        (
            "client.b",
            "/c/client.b.keyring",
            "unreadable",
            "cannot be read, decrypted or parsed on the Ansible controller: x <key>",
        ),
        ("client.c", "/c/client.c.keyring", "differs", "the keyring of client.a"),
        (
            "client.d",
            "/c/client.d.keyring",
            "differs",
            "carries a pending key line, which Ceph clients cannot read",
        ),
        (
            "client.e",
            "/c/client.e.keyring",
            "differs",
            "holds another key than the key in force next",
        ),
        (
            "client.f",
            "/c/client.f.keyring",
            "uncommitted",
            "git status failed (rc 128): fatal <key>",
        ),
        (
            "client.g",
            "/c/client.g.keyring",
            "uncommitted",
            "matches, but is not in the repository (git status: untracked)",
        ),
        (
            "client.h",
            "/c/client.h.keyring",
            "uncommitted",
            "matches, but is not in the repository (git status: ignored)",
        ),
        (
            "client.i",
            "/c/client.i.keyring",
            "uncommitted",
            "matches, but differs from the commit (git status: M): commit and push"
            " it, then osism apply configuration",
        ),
        (
            "client.j",
            "/c/client.j.keyring",
            "uncommitted",
            "matches, but differs from the commit (git status: A): commit and push"
            " it, then osism apply configuration",
        ),
        (
            "client.k",
            "/c/client.k.keyring",
            "uncommitted",
            "git status failed (rc 128)",
        ),
    ]
    assert k not in json.dumps(rows)


def test_checkout_no_entity_and_unreadable_without_message():
    rows = co_rows(
        [
            ("client.manila", {"failed": False}, git()),
            # unreadable without msg: no empty ": " part
            ("client.b", {"failed": False}, git()),
            ("client.c", ok_read("client.c"), git()),
        ],
        cluster={"client.b": flags(), "client.c": flags()},
    )
    assert [(r["result"], r["note"]) for r in rows] == [
        ("no-entity", "no such entity on the cluster (ceph auth export)"),
        ("unreadable", "cannot be read, decrypted or parsed on the Ansible controller"),
        ("matches", ""),
    ]
    assert (
        cephx_check_checkout([], {"results": []}, {"results": []}, {}, {}, "/c") == []
    )


def test_checkout_git_result_checked():
    # Q-V6: the git result needs rc (and stdout); "rc None" is never shown
    for g, message in (
        ({"stdout": ""}, "git status: the result has no rc"),
        ({"rc": 0}, "git status: the result has no stdout"),
        ({"rc": "0", "stdout": ""}, "git status: rc is not an int"),
    ):
        with pytest.raises(AnsibleFilterError) as e:
            co_rows([("client.c", ok_read("client.c"), g)])
        assert str(e.value) == message


def test_checkout_results_match_the_files():
    # the reads and git results are loops over the files, in their order
    files = co_files([("client.a", None, None), ("client.b", None, None)])
    reads = {"results": [dict(ok_read(f["name"]), item=f) for f in files]}
    gits = {"results": [git(item=f) for f in files]}
    fps = {f["name"]: "fp-" + f["name"] for f in files}
    cluster = {f["name"]: flags() for f in files}
    for r, g in (
        ({"results": reads["results"][:1]}, gits),
        (reads, {"results": gits["results"][::-1]}),
        ({"results": reads["results"][::-1]}, gits),
        (reads, {"results": gits["results"] + gits["results"][:1]}),
    ):
        with pytest.raises(AnsibleFilterError) as e:
            cephx_check_checkout(files, r, g, cluster, fps, "/c")
        assert str(e.value) == (
            "the reads of the checkout's keyring files are not those of its files"
        )


def test_configuration_directory_unset_fails():
    # configuration_directory unset or null: the checkout row fails (the
    # play reads nothing from a checkout it cannot name)
    rows = cephx_check_checkout([], {"results": []}, {"results": []}, {}, {}, None)
    assert rows == [
        row("checkout", "failed", "configuration_directory is not set", "manager")
    ]
    t = tests(checkout=rows, checkout_dir=None)
    assert t[3]["result"] == "failed"
    assert cephx_validator_lines(t)[3:5] == [
        "checkout: failed (Every keyring file in the checkout holds the key in force"
        " next and is unmodified in git.)",
        "  checkout @ manager: failed - configuration_directory is not set",
    ]


# --- check 5: the libvirt secrets of the compute nodes


def test_compute_secrets():
    found = {
        "results": [
            {
                "item": "c1",
                "files": [
                    {"path": "/s/%s.base64" % UN, "mtime": 1000.7},
                    {"path": "/s/%s.base64" % UC, "mtime": 2000.2},
                    {"path": "/s/other.base64", "mtime": 3000.0},
                ],
            },
            {"item": "c2", "unreachable": True, "msg": "gone"},
            {"item": "c3", "files": [], "failed": False},
        ]
    }
    assert cephx_compute_secrets(found, []) == [
        {
            "host": "c1",
            "reachable": True,
            "files": [UN + ".base64", UC + ".base64", "other.base64"],
            "mtime": 3000,
        },
        {"host": "c2", "reachable": False, "files": [], "mtime": 0},
        {"host": "c3", "reachable": True, "files": [], "mtime": 0},
    ]
    only = cephx_compute_secrets(found, [UN, UC])[0]
    assert only["files"] == [UN + ".base64", UC + ".base64"]
    assert only["mtime"] == 2000
    assert cephx_compute_secrets({"results": []}, []) == []


@pytest.mark.parametrize(
    "found,message",
    [
        ({}, "find of the libvirt secrets: the result has no results"),
        (
            {"results": [{"files": []}]},
            "find of the libvirt secrets: a result has no item",
        ),
        ({"results": [{"item": "c1"}]}, "find on c1: the result has no files"),
        ({"results": [{"item": "c1", "files": {}}]}, "find on c1: files is not a list"),
        (
            {"results": [{"item": "c1", "files": ["x"]}]},
            "find on c1: a file is not an object",
        ),
        (
            {"results": [{"item": "c1", "files": [{"mtime": 1}]}]},
            "find on c1: a file has no path",
        ),
        (
            {"results": [{"item": "c1", "files": [{"path": "/s/x.base64"}]}]},
            "find on c1: a file has no mtime",
        ),
        (
            {"results": [{"item": "c1", "files": [{"path": "/s/x", "mtime": "12"}]}]},
            "find on c1: a file's mtime is not a number",
        ),
        (
            {"results": [{"item": "c1", "files": [{"path": "/s/x", "mtime": True}]}]},
            "find on c1: a file's mtime is not a number",
        ),
        (
            {"results": [{"item": "c1", "failed": True, "msg": "x"}]},
            "find on c1 failed",
        ),
        (
            {"results": [{"item": "c1", "skipped": True}]},
            "find on c1: the find was skipped",
        ),
    ],
)
def test_compute_secrets_shape(found, message):
    # Q-V7: every file found has a path and an mtime (a missing mtime made
    # the cutoff too early); Q-V1: no results is not "no compute nodes"
    with pytest.raises(AnsibleFilterError) as e:
        cephx_compute_secrets(found, [])
    assert str(e.value) == message


def epoch(s):
    return calendar.timegm(time.strptime(s, "%Y-%m-%d %H:%M"))


def lstart(t):
    return time.strftime("%a %b %e %H:%M:%S %Y", time.gmtime(t))


def qemu(t, n, uuid=True):
    line = "%s /usr/libexec/qemu-kvm -name guest=instance-%08d,debug-threads=on -S" % (
        lstart(t),
        n,
    )
    if uuid:
        line += " -uuid %08d-aaaa-4bbb-8ccc-dddddddddddd" % n
    return line + " -blockdev {}"


CUTOFF = epoch("2026-11-20 10:00")
FILES = [UN + ".base64", UC + ".base64"]
FPS = {"client.nova": "fp-nova", "client.cinder": "fp-cinder"}


def fp_results(host="c1", files=FILES, fp=None, override=None):
    """Results of "Fingerprint the libvirt secrets": both copies of every
    file hold the key in force (nova's for UN, cinder's for UC)."""
    out = []
    for copy in ("kolla", "container"):
        for f in files:
            want = "fp-nova" if f.startswith(UN) else "fp-cinder"
            r = {
                "item": {"host": host, "file": f, "copy": copy, "ok": True},
                "key_fp": want,
                "in_force_fp": want,
            }
            if override and (f, copy) in override:
                r = override[(f, copy)](r)
            out.append(r)
    return {"results": out}


def container_results(host="c1", times=(CUTOFF - 600,) * 2, rc=0, lines=None, **kw):
    """The registered `stat -c '%Y %n'` in the container: a line per file
    with the given times."""
    if lines is None:
        lines = ["%d /etc/libvirt/secrets/%s" % (t, f) for t, f in zip(times, FILES)]
    r = cmd("\n".join(lines), rc, item={"host": host})
    r.update(kw)
    return {"results": [r]}


def ps_results(lines, host="c1", rc=0, **kw):
    r = cmd("\n".join(lines), rc, item={"host": host})
    r.update(kw)
    return {"results": [r]}


def compute(host="c1", files=FILES, mtime=CUTOFF, reachable=True):
    return [{"host": host, "reachable": reachable, "files": files, "mtime": mtime}]


def guests(
    comp=None,
    fps=None,
    container=None,
    ps=None,
    key_fps=FPS,
    rbd=UN,
    cinder=UC,
):
    return cephx_check_guests(
        compute() if comp is None else comp,
        fp_results() if fps is None else fps,
        container_results() if container is None else container,
        ps_results([]) if ps is None else ps,
        key_fps,
        secrets_dir="/etc/kolla/nova-libvirt/secrets",
        container="nova_libvirt",
        rbd_secret_uuid=rbd,
        cinder_rbd_secret_uuid=cinder,
        secret_uuids=[u for u in (rbd, cinder) if u],
    )


SECRETS_PASSED = (
    "libvirt loaded the secrets (%s, %s) at 2026-11-20 10:00:00 UTC, the later of"
    " kolla's copies in /etc/kolla/nova-libvirt/secrets and the nova_libvirt"
    " container's" % tuple(FILES)
)


def test_guests_before_and_after_the_cutoff():
    rows = guests(
        ps=ps_results(
            [
                qemu(CUTOFF - 3600, 11),
                qemu(CUTOFF, 12, uuid=False),
                qemu(CUTOFF + 60, 13),
                "Fri Nov 20 08:00:00 2026 /usr/sbin/libvirtd --listen",
                "Fri Nov 20 08:00:00 2026 qemu-img info x",
            ]
        )
    )
    old = (
        ", before libvirt loaded the current secrets: it holds the old key;"
        " live-migrate it (or stop and start it)"
    )
    assert rows == [
        {
            "entity": "secrets",
            "location": "c1",
            "result": "passed",
            "note": SECRETS_PASSED,
        },
        {
            "entity": "instance-00000011 (00000011-aaaa-4bbb-8ccc-dddddddddddd)",
            "location": "c1",
            "result": "failed",
            "note": "started 2026-11-20 09:00:00 UTC" + old,
        },
        {
            "entity": "instance-00000012",
            "location": "c1",
            "result": "failed",
            "note": "started 2026-11-20 10:00:00 UTC" + old,
        },
        {
            "entity": "instance-00000013 (00000013-aaaa-4bbb-8ccc-dddddddddddd)",
            "location": "c1",
            "result": "passed",
            "note": "started 2026-11-20 10:01:00 UTC",
        },
    ]


def test_guests_cutoff_is_the_later_time():
    # kolla's copy is older than the container's
    rows = guests(
        comp=compute(mtime=CUTOFF - 7200),
        ps=ps_results([qemu(CUTOFF - 60, 11)]),
    )
    assert rows[0]["note"].startswith("libvirt loaded the secrets")
    assert "at 2026-11-20 09:50:00 UTC" in rows[0]["note"]
    assert rows[1]["result"] == "passed"


def bad_note(*items):
    return (
        "; ".join(items) + ". osism apply nova has not given this host the current"
        " keys (or its nova_libvirt container has not been restarted since); its"
        " guests are not compared"
    )


def test_guests_secret_stale_in_kollas_copy():
    def stale(r):
        return dict(r, key_fp="fp-old")

    rows = guests(
        fps=fp_results(override={(FILES[0], "kolla"): stale}),
        ps=ps_results([qemu(CUTOFF + 60, 11)]),
    )
    assert rows == [
        {
            "entity": "secrets",
            "location": "c1",
            "result": "failed",
            "note": bad_note(
                FILES[0] + ": kolla's copy holds another key than the one in force"
                " for client.nova"
            ),
        }
    ]


def test_guests_secret_stale_in_containers_copy_without_uuids():
    def stale(r):
        return dict(r, key_fp="fp-old")

    rows = guests(
        fps=fp_results(override={(FILES[1], "container"): stale}),
        rbd="",
        cinder="",
    )
    assert rows[0]["note"] == bad_note(
        FILES[1] + ": the nova_libvirt container's copy holds another key than the"
        " one in force for client.nova or client.cinder"
    )
    assert len(rows) == 1


def test_guests_secret_unreadable():
    def skipped(r):
        return {"item": dict(r["item"], ok=False), "skipped": True}

    def nokey(r):
        r = dict(r)
        del r["key_fp"]
        return dict(r, failed=False, msg="no key")

    fps = fp_results(
        override={(FILES[0], "kolla"): skipped, (FILES[1], "container"): nokey}
    )
    # the container's copy of UN has no fingerprint result at all
    fps["results"] = [
        r
        for r in fps["results"]
        if not (r["item"]["file"] == FILES[0] and r["item"]["copy"] == "container")
    ]
    rows = guests(fps=fps, ps=ps_results([qemu(CUTOFF + 60, 11)]))
    assert rows == [
        {
            "entity": "secrets",
            "location": "c1",
            "result": "failed",
            "note": bad_note(
                FILES[0] + ": kolla's copy cannot be read",
                FILES[0] + ": the nova_libvirt container's copy cannot be read",
                FILES[1] + ": the nova_libvirt container's copy does not hold a"
                " cephx key",
            ),
        }
    ]


def test_guests_secret_without_known_entity_is_not_compared():
    # client.nova and client.cinder are not on the cluster: nothing to expect
    rows = guests(fps={"results": []}, key_fps={}, ps=ps_results([]))
    assert rows == [
        {
            "entity": "secrets",
            "location": "c1",
            "result": "passed",
            "note": SECRETS_PASSED,
        }
    ]


def unknown_times(why):
    return [
        row(
            "secrets",
            "failed",
            "the nova_libvirt container's copies of the secrets (%s, %s) cannot be"
            " read (%s): cannot establish when libvirt loaded the secrets; its"
            " guests are not compared" % (FILES[0], FILES[1], why),
            "c1",
        )
    ]


def test_guests_container_copies_unreadable():
    # Q-V3, T-11: when the container's times cannot be read the guests are
    # not compared (kolla's time alone may be too early a cutoff)
    old_guest = ps_results([qemu(CUTOFF - 60, 11)])
    rows = guests(container=container_results(times=(), rc=1), ps=old_guest)
    assert rows == unknown_times("rc 1")
    # Q-V9, T-14: no result for the host at all
    rows = guests(container={"results": []}, ps=old_guest)
    assert rows == unknown_times("no result")
    rows = guests(container=container_results(lines=["x"]), ps=old_guest)
    assert rows == unknown_times("stat did not print a time for each")


PARTIAL = [
    # one valid line, one malformed
    ["%d /etc/libvirt/secrets/%s" % (CUTOFF, FILES[0]), "garbage"],
    # one line only
    ["%d /etc/libvirt/secrets/%s" % (CUTOFF, FILES[0])],
    # the same secret twice
    ["%d /etc/libvirt/secrets/%s" % (CUTOFF, FILES[0])] * 2,
    # an unexpected secret instead of the second
    [
        "%d /etc/libvirt/secrets/%s" % (CUTOFF, FILES[0]),
        "%d /etc/libvirt/secrets/other.base64" % CUTOFF,
    ],
    # a time that is not a number
    [
        "%d /etc/libvirt/secrets/%s" % (CUTOFF, FILES[0]),
        "1.5 /etc/libvirt/secrets/%s" % FILES[1],
    ],
    # a valid pair with an unexpected line between them
    [
        "%d /etc/libvirt/secrets/%s" % (CUTOFF, FILES[0]),
        "",
        "%d /etc/libvirt/secrets/%s" % (CUTOFF, FILES[1]),
    ],
]


@pytest.mark.parametrize("lines", PARTIAL)
def test_partial_container_timestamps_fail_host(lines):
    # Q-V3 (amended): every expected secret has exactly one valid time in
    # the container's answer, or the host fails and its guests are not
    # compared
    rows = guests(
        container=container_results(lines=lines),
        ps=ps_results([qemu(CUTOFF - 60, 11), qemu(CUTOFF + 60, 12)]),
    )
    assert rows == unknown_times("stat did not print a time for each")


def test_guests_container_times_complete():
    # both times, in either order: compared against the later
    lines = [
        "%d /etc/libvirt/secrets/%s" % (CUTOFF + 60, FILES[1]),
        "%d /etc/libvirt/secrets/%s" % (CUTOFF - 60, FILES[0]),
    ]
    rows = guests(
        container=container_results(lines=lines),
        ps=ps_results([qemu(CUTOFF + 30, 11)]),
    )
    assert rows[0]["result"] == "passed"
    assert "at 2026-11-20 10:01:00 UTC" in rows[0]["note"]
    assert rows[1]["result"] == "failed"


def test_guests_secret_without_rbd_uuid_is_either_key():
    # Q-V8: only non-empty UUIDs are compared: with rbd_secret_uuid unset
    # a file named exactly .base64 is not client.nova's
    f = ".base64"
    fps = {
        "results": [
            {
                "item": {"host": "c1", "file": f, "copy": copy, "ok": True},
                "key_fp": "fp-cinder",
            }
            for copy in ("kolla", "container")
        ]
    }
    rows = guests(
        comp=compute(files=[f]),
        fps=fps,
        container=container_results(lines=["%d /etc/libvirt/secrets/.base64" % CUTOFF]),
        rbd="",
        cinder=UC,
    )
    assert rows[0]["result"] == "passed"


def test_guests_fingerprint_shape():
    fps = fp_results(override={(FILES[0], "kolla"): lambda r: dict(r, key_fp=None)})
    with pytest.raises(AnsibleFilterError) as e:
        guests(fps=fps)
    assert str(e.value) == ("cephx_keyring of the libvirt secrets: key_fp is not a str")


def test_guests_ps_failed_and_unreachable():
    k = key()
    rows = guests(ps=ps_results([], rc=1, stderr="error " + k))
    assert rows[1] == {
        "entity": "processes",
        "location": "c1",
        "result": "failed",
        "note": "ps failed (rc 1): error <key>",
    }
    assert k not in json.dumps(rows)
    # T-4: no empty stderr part
    rows = guests(ps=ps_results([], rc=1))
    assert rows[1]["note"] == "ps failed (rc 1)"
    rows = guests(ps={"results": [{"item": {"host": "c1"}, "unreachable": True}]})
    assert rows[1] == {
        "entity": "host",
        "location": "c1",
        "result": "failed",
        "note": "the host cannot be reached",
    }
    # Q-V9, T-14: no ps result for the host
    rows = guests(ps={"results": []})
    assert rows[1]["note"] == "ps failed (no result)"
    with pytest.raises(AnsibleFilterError) as e:
        guests(ps=ps_results([], rc=None))
    assert str(e.value) == "ps on c1: rc is not an int"


def test_unreachable_host_row():
    # an unreachable compute host is a failed row of its own (not a stop),
    # at the find, at the container's times or at ps; the hosts that can be
    # reached are still checked
    found = {
        "results": [
            {"item": "dead", "unreachable": True, "msg": "gone", "changed": False},
            {
                "item": "c1",
                "failed": False,
                "files": [{"path": "/s/" + f, "mtime": CUTOFF - 3600} for f in FILES],
            },
        ]
    }
    comp = cephx_compute_secrets(found, [UN, UC])
    assert comp[0] == {"host": "dead", "reachable": False, "files": [], "mtime": 0}
    host_row = row("host", "failed", "the host cannot be reached", "dead")
    rows = guests(comp=comp, ps=ps_results([qemu(CUTOFF + 60, 11)]))
    assert rows[0] == host_row
    assert [r["result"] for r in rows[1:]] == ["passed", "passed"]
    # the container's times: the host row only, no guests compared
    gone = {"item": {"host": "c1"}, "unreachable": True, "msg": "gone"}
    rows = guests(container={"results": [gone]}, ps=ps_results([]))
    assert rows == [row("host", "failed", "the host cannot be reached", "c1")]
    # and the monitor copies on an unreachable monitor host
    rows = cephx_check_monitor(
        {"results": [{"item": ["dead", "client.a"], "unreachable": True}]},
        {"results": []},
        {"client.a": "fpa"},
    )
    assert rows == [host_row | {"entity": "client.a"}]


def test_guests_unreachable_and_without_secrets():
    comp = compute(host="dead", files=[], mtime=0, reachable=False) + compute(
        host="c2", files=[], mtime=0
    )
    none = {"results": []}
    rows = guests(comp=comp, fps=none, container=none, ps=none)
    skipped = {
        "entity": "secrets",
        "location": "c2",
        "result": "skipped",
        "note": "no libvirt secrets in /etc/kolla/nova-libvirt/secrets for %s, %s:"
        " no Nova with Ceph on this host" % (UN, UC),
    }
    assert rows == [
        {
            "entity": "host",
            "location": "dead",
            "result": "failed",
            "note": "the host cannot be reached",
        },
        skipped,
    ]
    rows = guests(comp=comp[1:], fps=none, container=none, ps=none, rbd="", cinder=None)
    assert rows[0]["note"] == (
        "no libvirt secrets in /etc/kolla/nova-libvirt/secrets: no Nova with Ceph"
        " on this host"
    )
    assert guests(comp=[], fps=none, container=none, ps=none) == []


# --- collected results and printed lines


def row(entity, result, note="", location="cluster"):
    return {"entity": entity, "location": location, "result": result, "note": note}


def tests(**kw):
    args = dict(
        old=[],
        monitor=[row("client.a", "matches", location="m1")],
        checkout=[row("client.a", "matches", location="/c/a")],
        guests=[row("secrets", "passed", "loaded", "c1")],
        aes_allowed=True,
        strict=False,
        checkout_dir="/opt/configuration",
        compute_hosts=["c1"],
    )
    pending = kw.pop("pending", [])
    args.update(kw)
    return cephx_validator_tests(pending, **args)


OLD_NOTE = (
    "No entity's key in force is of the old type aes. Keys of that type are"
    " listed, but fail the check only with ceph_validate_strict true or when"
    " auth_allowed_ciphers excludes aes (it %s aes)."
)


def test_validator_tests_passed():
    t = tests()
    assert [x["name"] for x in t] == [
        "pending-keys",
        "old-key-type",
        "monitor-copies",
        "checkout",
        "running-guests",
    ]
    assert t[0] == {
        "name": "pending-keys",
        "result": "passed",
        "note": "No entity has a pending key (a pending key is a rotation that is"
        " not finished).",
        "data": [],
    }
    assert t[1]["note"] == OLD_NOTE % "allows"
    assert t[2]["note"] == (
        "Every /etc/ceph/ceph.<entity>.keyring on the monitor hosts holds the key"
        " in force next."
    )
    assert t[3]["note"] == (
        "Every keyring file in /opt/configuration holds the key in force next and"
        " is unmodified in git."
    )
    assert t[4]["note"] == (
        "Every QEMU process on the compute nodes started after libvirt loaded the"
        " current secrets."
    )
    assert [x["result"] for x in t] == ["passed"] * 5
    assert t[4]["data"] == [row("secrets", "passed", "loaded", "c1")]


def test_validator_tests_failed():
    aes = [row("client.a", "aes", "old")]
    assert tests(old=aes)[1]["result"] == "passed"
    assert tests(old=aes, strict=True)[1]["result"] == "failed"
    t = tests(old=aes, aes_allowed=False)[1]
    assert t["result"] == "failed"
    assert t["note"] == OLD_NOTE % "excludes"
    assert tests(old=[], strict=True)[1]["result"] == "passed"
    assert tests(pending=[row("client.a", "pending")])[0]["result"] == "failed"
    assert tests(monitor=[row("a", "missing")])[2]["result"] == "failed"
    assert tests(checkout=[row("a", "no-entity")])[3]["result"] == "passed"
    assert tests(checkout=[row("a", "uncommitted")])[3]["result"] == "failed"
    assert tests(guests=[row("secrets", "skipped")])[4]["result"] == "passed"
    assert tests(guests=[row("i", "failed")])[4]["result"] == "failed"


def test_validator_tests_without_compute_hosts_or_checkout():
    t = tests(compute_hosts=[], guests=[], checkout_dir=None)
    assert t[4] == {
        "name": "running-guests",
        "result": "skipped",
        "note": "no compute hosts (inventory group compute): nothing to check",
        "data": [],
    }
    assert t[3]["note"] == (
        "Every keyring file in the checkout holds the key in force next and is"
        " unmodified in git."
    )


def test_validator_lines():
    t = tests(
        pending=[row("client.a", "pending", "commit it")],
        monitor=[
            row("client.a", "matches", "/etc/ceph/x", "m1"),
            row("client.b", "missing", "", "m1"),
        ],
        guests=[row("secrets", "passed", "ok", "c1"), row("i", "failed", "old", "c1")],
    )
    t[0]["note"] = "  padded note \n"
    assert cephx_validator_lines(t) == [
        "pending-keys: failed (padded note)",
        "  client.a @ cluster: pending - commit it",
        "old-key-type: passed (" + OLD_NOTE % "allows" + ")",
        "monitor-copies: failed (Every /etc/ceph/ceph.<entity>.keyring on the"
        " monitor hosts holds the key in force next.)",
        "  client.b @ m1: missing",
        "checkout: passed (Every keyring file in /opt/configuration holds the key"
        " in force next and is unmodified in git.)",
        "running-guests: failed (Every QEMU process on the compute nodes started"
        " after libvirt loaded the current secrets.)",
        "  i @ c1: failed - old",
    ]
    assert cephx_validator_lines([]) == []


@pytest.mark.parametrize(
    "value,message",
    [
        (None, "ceph mon dump: did not print JSON"),
        ("", "ceph mon dump: did not print JSON"),
        ("x", "ceph mon dump: did not print JSON"),
        ("[]", "ceph mon dump: did not print a JSON object"),
    ],
)
def test_aes_allowed_needs_a_monitor_map(value, message):
    # the play's guard lets only output starting with { through; anything
    # else is refused without the input in the message
    with pytest.raises(AnsibleFilterError) as e:
        cephx_aes_allowed(value)
    assert str(e.value) == message


@pytest.mark.parametrize("stdout", ["{cut off", '{"osds": '])
def test_pending_osd_dump_unreadable(stdout):
    k = key()
    with pytest.raises(AnsibleFilterError) as e:
        cephx_check_pending(
            {"client.osd-lockbox." + OSD_FSID: flags(True)},
            cmd(stdout + k),
            SERVICES,
            [],
        )
    assert str(e.value) == "ceph osd dump: did not print JSON"


# --- the keyrings of the compared entities (ceph auth get)


def test_auth_get_failed():
    # one sentence per failed read, stderr masked; stdout (the keyring) is
    # never read; '' when every read worked
    k = key()
    keyring = "[client.a]\n\tkey = %s\n" % k
    reads = {
        "results": [
            cmd(keyring, item="client.a"),
            cmd(rc=22, stderr="Error EINVAL: bad key " + k, item="client.b"),
            cmd(rc=2, item="client.c"),
        ]
    }
    assert cephx_auth_get_failed(reads) == (
        "ceph auth get client.b failed (rc 22): Error EINVAL: bad key <key>."
        " ceph auth get client.c failed (rc 2)."
    )
    assert cephx_auth_get_failed({"results": [cmd(keyring, item="client.a")]}) == ""
    assert cephx_auth_get_failed({"results": [], "skipped": True}) == ""


def test_auth_get_failed_result_checked():
    k = key()
    for registered, message in (
        ({}, "ceph auth get: the result has no results"),
        ({"results": [{"rc": 0, "stdout": k}]}, "ceph auth get: a result has no item"),
        (
            {"results": [{"rc": 0, "item": "client.a"}]},
            "ceph auth get client.a: the result has no stdout",
        ),
    ):
        with pytest.raises(AnsibleFilterError) as e:
            cephx_auth_get_failed(registered)
        assert str(e.value) == message
