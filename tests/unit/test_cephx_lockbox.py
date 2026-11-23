import base64
import json
import os
import struct

import pytest
from ansible.errors import AnsibleFilterError
from ansible.utils.unsafe_proxy import AnsibleUnsafeText

from cephx_lockbox import (
    FilterModule,
    cephx_lockbox_copies,
    cephx_lockbox_doubled,
    cephx_lockbox_done,
    cephx_lockbox_get_refusal,
    cephx_lockbox_osds,
    cephx_lockbox_two_tags,
    cephx_lockbox_unwritten,
    cephx_osd_back,
    cephx_osd_back_until,
    cephx_osd_lvs,
    cephx_osd_state,
)

U0 = "aaaaaaaa-0000-4000-8000-000000000000"
U1 = "bbbbbbbb-1111-4111-8111-111111111111"
U2 = "cccccccc-2222-4222-8222-222222222222"
U3 = "dddddddd-3333-4333-8333-333333333333"
L0 = "client.osd-lockbox." + U0
L3 = "client.osd-lockbox." + U3
SECRET = "ceph.cephx_lockbox_secret="


def key():
    """A random aes256k key, never printed."""
    secret = os.urandom(32)
    header = struct.pack("<HIIH", 2, 1700000000, 0, len(secret))
    return base64.b64encode(header + secret).decode()


def tags(osd, fsid, secret=None, *extra):
    t = ["ceph.block_device=/dev/x", "ceph.osd_fsid=" + fsid, "ceph.osd_id=%s" % osd]
    if secret is not None:
        t.append(SECRET + secret)
    return ",".join(t + list(extra) + ["ceph.type=block"])


def lv(vg, name, lv_tags):
    return {"vg_name": vg, "lv_name": name, "lv_tags": lv_tags}


def report(*lvs):
    return json.dumps({"report": [{"lv": list(lvs)}]})


K0, K1 = key(), key()
BLOCK0 = lv("ceph-0", "osd-block-0", tags(0, U0, K0))
DB0 = lv("ceph-0db", "osd-db-0", tags(0, U0, K0))
BLOCK1 = lv("ceph-1", "osd-block-1", tags(1, U1, K1))
BLOCK2 = lv("ceph-2", "osd-block-2", tags(2, U2, ""))
# An LV of a destroyed osd.0: same id, another osd_fsid.
OLD0 = lv("ceph-old", "osd-block-old0", tags(0, U3, K1))
ROOT = lv("ubuntu-vg", "root", "")
HOST = report(BLOCK0, DB0, BLOCK1, BLOCK2, OLD0, ROOT)


def guarded(name):
    return FilterModule().filters()[name]


def test_filters_registered():
    filters = FilterModule().filters()
    assert set(filters) == {
        "cephx_osd_lvs",
        "cephx_lockbox_doubled",
        "cephx_lockbox_two_tags",
        "cephx_lockbox_osds",
        "cephx_lockbox_copies",
        "cephx_lockbox_unwritten",
        "cephx_lockbox_get_refusal",
        "cephx_lockbox_done",
        "cephx_osd_state",
        "cephx_osd_back",
        "cephx_osd_back_until",
    }
    assert filters["cephx_osd_lvs"].__wrapped__ is cephx_osd_lvs
    assert filters["cephx_lockbox_doubled"].__wrapped__ is cephx_lockbox_doubled
    assert filters["cephx_lockbox_two_tags"].__wrapped__ is cephx_lockbox_two_tags
    assert filters["cephx_lockbox_osds"].__wrapped__ is cephx_lockbox_osds
    assert filters["cephx_lockbox_copies"].__wrapped__ is cephx_lockbox_copies
    assert filters["cephx_lockbox_unwritten"].__wrapped__ is cephx_lockbox_unwritten
    assert filters["cephx_lockbox_get_refusal"].__wrapped__ is cephx_lockbox_get_refusal
    assert filters["cephx_lockbox_done"].__wrapped__ is cephx_lockbox_done
    assert filters["cephx_osd_state"].__wrapped__ is cephx_osd_state
    assert filters["cephx_osd_back"].__wrapped__ is cephx_osd_back
    assert filters["cephx_osd_back_until"].__wrapped__ is cephx_osd_back_until


# cephx_osd_lvs


def test_osd_lvs_block_and_db():
    assert cephx_osd_lvs(HOST, 0, U0) == [
        {"name": "ceph-0/osd-block-0", "secret": K0},
        {"name": "ceph-0db/osd-db-0", "secret": K0},
    ]


def test_osd_lvs_match_both_tags():
    # osd.0 with another osd_fsid is another OSD (destroyed and recreated).
    assert cephx_osd_lvs(HOST, 0, U3) == [
        {"name": "ceph-old/osd-block-old0", "secret": K1}
    ]
    assert cephx_osd_lvs(HOST, 1, U1) == [{"name": "ceph-1/osd-block-1", "secret": K1}]
    assert cephx_osd_lvs(HOST, 1, U0) == []
    assert cephx_osd_lvs(HOST, 3, U3) == []


def test_osd_lvs_exact_tags_not_prefixes():
    # Tags are compared whole: osd.10's LV is not osd.1's, and an osd_fsid
    # that starts with another one's is another OSD's.
    host = report(
        lv("ceph-10", "osd-block-10", tags(10, U1, K0)),
        lv("ceph-long", "osd-block-long", tags(1, U1 + "0", K0)),
        lv("ceph-1", "osd-block-1", tags(1, U1, K1)),
    )
    assert cephx_osd_lvs(host, 1, U1) == [{"name": "ceph-1/osd-block-1", "secret": K1}]
    assert cephx_osd_lvs(host, 1, U1[:-1]) == []
    assert cephx_osd_lvs(host, 0, U1) == []
    assert cephx_osd_lvs(host, 10, U1) == [
        {"name": "ceph-10/osd-block-10", "secret": K0}
    ]


def test_osd_lvs_id_as_digits():
    # The play passes the id through an include's vars: a string of digits.
    assert cephx_osd_lvs(HOST, "1", U1) == [
        {"name": "ceph-1/osd-block-1", "secret": K1}
    ]


@pytest.mark.parametrize(
    "osd_id", ["x", "", "-1", "1.0", " 1", "1234567890", True, None, -1, 1.0]
)
def test_osd_lvs_id_refused(osd_id):
    # Q-L3: the id is an int (or the play's digits), never compared as text.
    for f in (cephx_osd_lvs, cephx_lockbox_doubled):
        with pytest.raises(AnsibleFilterError) as e:
            f(HOST, osd_id, U1)
        assert e.value.message == "lvs: the OSD id is not a number"


@pytest.mark.parametrize("osd_fsid", ["", None, 5])
def test_osd_lvs_fsid_refused(osd_fsid):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_osd_lvs(HOST, 0, osd_fsid)
    assert e.value.message == "lvs: the osd_fsid is not a non-empty str"


def test_osd_lvs_unencrypted():
    # ceph-volume tags an unencrypted OSD's LVs with an empty secret.
    assert cephx_osd_lvs(HOST, 2, U2) == [{"name": "ceph-2/osd-block-2", "secret": ""}]
    host = report(lv("v", "a", tags(2, U2)))
    assert cephx_osd_lvs(host, 2, U2) == [{"name": "v/a", "secret": ""}]


def test_osd_lvs_ansible_text():
    assert cephx_osd_lvs(AnsibleUnsafeText(HOST), 1, AnsibleUnsafeText(U1)) == [
        {"name": "ceph-1/osd-block-1", "secret": K1}
    ]


@pytest.mark.parametrize(
    "lv_tags, secret",
    [
        (tags(0, U0, ""), ""),
        (tags(0, U0, "ab=cd"), "ab=cd"),
        (tags(0, U0, "S-0", "ceph.cephx_lockbox_secretX=Q"), "S-0"),
        (tags(0, U0, None, "ceph.cephx_lockbox_secretX=Q"), ""),
        # Q-L2: two secret tags, whatever their values: no secret (the play
        # stops on cephx_lockbox_doubled before it would use one).
        (tags(0, U0, "", SECRET + "S-2"), ""),
        (tags(0, U0, "S-1", SECRET + "S-2"), ""),
        (tags(0, U0, "S-1", SECRET + "S-1"), ""),
    ],
)
def test_osd_lvs_secret(lv_tags, secret):
    assert cephx_osd_lvs(report(lv("v", "a", lv_tags)), 0, U0) == [
        {"name": "v/a", "secret": secret}
    ]


def test_osd_lvs_tags_not_trimmed():
    lv_tags = " ceph.osd_id=0,ceph.osd_fsid=%s,%sS" % (U0, SECRET)
    assert cephx_osd_lvs(report(lv("v", "a", lv_tags)), 0, U0) == []


def test_osd_lvs_without_tags():
    # An LV without tags: lvs prints an empty lv_tags.
    assert cephx_osd_lvs(report(lv("v", "a", ""), DB0), 0, U0) == [
        {"name": "ceph-0db/osd-db-0", "secret": K0}
    ]


@pytest.mark.parametrize(
    "stdout",
    [
        json.dumps({"report": [{"lv": [BLOCK0, DB0]}], "log": []}),
        json.dumps({"report": [{"lv": [BLOCK0]}, {"lv": [DB0]}]}),
    ],
)
def test_osd_lvs_report_shapes(stdout):
    assert [x["name"] for x in cephx_osd_lvs(stdout, 0, U0)] == [
        "ceph-0/osd-block-0",
        "ceph-0db/osd-db-0",
    ]


@pytest.mark.parametrize(
    "stdout",
    [json.dumps({"report": [{"lv": []}]}), json.dumps({"report": []})],
)
def test_osd_lvs_empty_report(stdout):
    assert cephx_osd_lvs(stdout, 0, U0) == []


NO_LV_LIST = "lvs: an entry of the report has no lv list"


@pytest.mark.parametrize(
    "stdout, message",
    [
        ('{"report": [{"lv": [%s,' % json.dumps(BLOCK0), "lvs: did not print JSON"),
        ("", "lvs: did not print JSON"),
        (None, "lvs: did not print JSON"),
        ("[]", "lvs: did not print a JSON object"),
        ('"x"', "lvs: did not print a JSON object"),
        ("{}", "lvs: the object has no report"),
        (json.dumps({"report": {"lv": [BLOCK0]}}), "lvs: report is not a list"),
        (json.dumps({"report": "x"}), "lvs: report is not a list"),
        (json.dumps({"report": None}), "lvs: report is not a list"),
        # Q-L1: exactly {"report": [{"lv": [{...}]}]}: no flattening, no
        # null entries.
        (json.dumps({"report": [{}]}), NO_LV_LIST),
        (json.dumps({"report": [None, {"lv": [BLOCK0]}]}), NO_LV_LIST),
        (json.dumps({"report": [{"lv": BLOCK0}]}), NO_LV_LIST),
        (json.dumps({"report": [{"lv": None}]}), NO_LV_LIST),
        (json.dumps({"report": [{"lv": [[BLOCK0]]}]}), "lvs: an LV is not an object"),
        (
            json.dumps({"report": [{"lv": [None, BLOCK0]}]}),
            "lvs: an LV is not an object",
        ),
        (report(lv("v", "a", None), BLOCK0), "lvs: an LV's lv_tags is not a str"),
        (report(lv("v", "a", 5), BLOCK0), "lvs: an LV's lv_tags is not a str"),
        (
            report(lv("v", "a", ["ceph.osd_id=0"]), BLOCK0),
            "lvs: an LV's lv_tags is not a str",
        ),
        (report({"vg_name": "v", "lv_name": "a"}, BLOCK0), "lvs: an LV has no lv_tags"),
        (
            report({"lv_name": "a", "lv_tags": tags(0, U0, K0)}),
            "lvs: an LV has no vg_name",
        ),
        (
            report({"vg_name": "v", "lv_tags": tags(0, U0, K0)}),
            "lvs: an LV has no lv_name",
        ),
        # Q-L3: names are text, on every LV (lvs prints the fields asked
        # for on each).
        (report(lv(None, "a", tags(0, U0, K0))), "lvs: an LV's vg_name is not a str"),
        (report(lv("v", 6, "")), "lvs: an LV's lv_name is not a str"),
        (report({"lv_name": "r", "lv_tags": ""}, BLOCK0), "lvs: an LV has no vg_name"),
        # lvs lists each LV once.
        (report(BLOCK0, BLOCK0), "lvs: an LV is listed twice"),
        (report(ROOT, DB0, ROOT), "lvs: an LV is listed twice"),
    ],
)
def test_osd_lvs_garbage(stdout, message):
    # The output carries keys: the message names the command, never the text.
    for f in (cephx_osd_lvs, cephx_lockbox_doubled):
        with pytest.raises(AnsibleFilterError) as e:
            f(stdout, 0, U0)
        assert e.value.message == message
        assert K0 not in str(e.value)


def test_osd_lvs_guarded_no_key():
    # Through the decorator, as the play calls it.
    with pytest.raises(AnsibleFilterError) as e:
        guarded("cephx_osd_lvs")(report(BLOCK0, BLOCK0), 0, U0)
    assert K0 not in str(e.value)


# cephx_lockbox_doubled


def test_doubled():
    k = key()
    two = lv("ceph-0", "osd-block-0", tags(0, U0, K0, SECRET + k))
    empty = lv("ceph-0db", "osd-db-0", tags(0, U0, "", SECRET))
    other = lv("ceph-old", "osd-block-old0", tags(0, U3, K0, SECRET + k))
    out = cephx_lockbox_doubled(report(two, empty, other, BLOCK1), 0, U0)
    assert out == ["ceph-0/osd-block-0", "ceph-0db/osd-db-0"]
    assert K0 not in repr(out) and k not in repr(out)
    assert cephx_lockbox_doubled(HOST, 0, U0) == []
    assert cephx_lockbox_doubled(report(), 0, U0) == []


def test_doubled_names_masked():
    # A name that looks like a key is masked (vg and lv each).
    k = key()
    named = lv(k, k, tags(0, U0, K0, SECRET + K0))
    assert cephx_lockbox_doubled(report(named), "0", U0) == ["<key>/<key>"]


# cephx_lockbox_two_tags


def test_two_tags_after_write_stop():
    text = cephx_lockbox_two_tags(
        ["ceph-1/osd-block-1"], "1", ["ceph-1/osd-block-1", "lockbox.keyring"]
    )
    assert text == (
        "Two ceph.cephx_lockbox_secret tags on ceph-1/osd-block-1 (osd.1) after"
        " the writes (written: the tag of ceph-1/osd-block-1, lockbox.keyring)."
        " Which copy is in force is not known, so osd.1 is not restarted; its"
        " new lockbox key is not in force yet (the old key still works). Check"
        " the host's LVM (lvs -o lv_name,lv_tags): each LV of osd.1 needs one"
        " ceph.cephx_lockbox_secret tag, with the key in force next."
    )
    assert "Nothing was changed" not in text


def test_two_tags_after_write_stop_two_lvs():
    text = cephx_lockbox_two_tags(["v/a", "v/b"], 0, ["v/a"])
    assert text.startswith(
        "Two ceph.cephx_lockbox_secret tags on v/a, v/b (osd.0) after the writes"
        " (written: the tag of v/a). Which copy"
    )


def test_two_tags_before_the_writes():
    # Found by the read before the writes (after the classification found
    # none): no copy written.
    text = cephx_lockbox_two_tags(["ceph-1/osd-block-1"], 1, [])
    assert text == (
        "Two ceph.cephx_lockbox_secret tags on ceph-1/osd-block-1 (osd.1):"
        " refused. Which copy is in force is not known: no copy was written, and"
        " osd.1 is not restarted. Check the host's LVM (lvs -o lv_name,lv_tags):"
        " each LV of osd.1 needs one ceph.cephx_lockbox_secret tag, with the key"
        " in force next."
    )


def test_two_tags_none():
    assert cephx_lockbox_two_tags([], 1, []) == ""
    assert cephx_lockbox_two_tags([], 1, ["v/a"]) == ""


@pytest.mark.parametrize(
    "doubled, written",
    [("v/a", []), (["v/a"], "v/a"), (None, []), (["v/a"], None)],
)
def test_two_tags_refused(doubled, written):
    with pytest.raises(AnsibleFilterError):
        cephx_lockbox_two_tags(doubled, 1, written)


# cephx_lockbox_osds

HOSTS = [
    {"osd": 0, "osd_fsid": U0, "up": True, "host": "node-0"},
    {"osd": 1, "osd_fsid": U1, "up": True, "host": "node-0"},
    {"osd": 2, "osd_fsid": U2, "up": True, "host": "node-1"},
    {"osd": 3, "osd_fsid": U3, "up": False, "host": "node-1"},
]


def lvs_result(host, stdout, rc=0, stderr="", **more):
    return dict(
        {
            "item": host,
            "rc": rc,
            "stdout": stdout,
            "stderr": stderr,
            "failed": False,
            "changed": False,
        },
        **more,
    )


LVS = {
    "results": [
        lvs_result("node-0", report(BLOCK0, DB0, BLOCK1, OLD0, ROOT)),
        lvs_result("node-1", report(BLOCK2)),
    ]
}
# The loop over no host (no OSD up, or lockbox keys not asked for).
NO_LOOP = {"results": [], "skipped": True, "changed": False, "msg": "No items"}


def osd(o, lvs, encrypted, doubled=()):
    return dict(
        o,
        entity="client.osd-lockbox." + o["osd_fsid"],
        lvs=lvs,
        encrypted=encrypted,
        doubled=list(doubled),
    )


def test_lockbox_osds():
    assert cephx_lockbox_osds(HOSTS, LVS, [L0, L3]) == [
        osd(HOSTS[0], 2, True),
        osd(HOSTS[1], 1, True),
        osd(HOSTS[2], 1, False),
        osd(HOSTS[3], 0, True),
    ]


def test_lockbox_osds_down_without_entity():
    # A down OSD's host is not read: encrypted when its lockbox entity exists.
    assert cephx_lockbox_osds(HOSTS[3:], NO_LOOP, [L0]) == [osd(HOSTS[3], 0, False)]


def test_lockbox_osds_up_entity_does_not_count():
    assert cephx_lockbox_osds(HOSTS[2:3], LVS, ["client.osd-lockbox." + U2]) == [
        osd(HOSTS[2], 1, False)
    ]


def test_lockbox_osds_secret_with_value_counts():
    # One parser (Q-L2): an LV with one secret tag that has a value is
    # encrypted, an empty one is not; two tags are doubled (and encrypted
    # if either has a value), which the classification refuses.
    def one(lv_tags):
        lvs = {"results": [lvs_result("node-0", report(lv("v", "a", lv_tags)))]}
        return cephx_lockbox_osds(HOSTS[:1], lvs, [])

    assert one(tags(0, U0, "S")) == [osd(HOSTS[0], 1, True)]
    assert one(tags(0, U0, "")) == [osd(HOSTS[0], 1, False)]
    assert one(tags(0, U0)) == [osd(HOSTS[0], 1, False)]
    assert one(tags(0, U0, "", SECRET + "S")) == [osd(HOSTS[0], 1, True, ["v/a"])]
    assert one(tags(0, U0, "", SECRET)) == [osd(HOSTS[0], 1, False, ["v/a"])]


def test_lockbox_osds_two_secret_tags():
    # An LV of the OSD with two ceph.cephx_lockbox_secret tags (with values
    # or not) is named in doubled: names only, never a tag.
    k = key()
    two = lv("ceph-0", "osd-block-0", tags(0, U0, K0, SECRET + k))
    empty = lv("ceph-0db", "osd-db-0", tags(0, U0, "", SECRET))
    other = lv("ceph-old", "osd-block-old0", tags(0, U3, K0, SECRET + k))
    lvs = {"results": [lvs_result("node-0", report(two, empty, other))]}
    out = cephx_lockbox_osds(HOSTS[:1], lvs, [])
    assert out == [osd(HOSTS[0], 2, True, ["ceph-0/osd-block-0", "ceph-0db/osd-db-0"])]
    assert K0 not in repr(out) and k not in repr(out)
    # A name that looks like a key is masked (vg and lv each).
    named = lv(k, k, tags(0, U0, K0, SECRET + K0))
    lvs = {"results": [lvs_result("node-0", report(named))]}
    assert cephx_lockbox_osds(HOSTS[:1], lvs, [])[0]["doubled"] == ["<key>/<key>"]
    # A down OSD's host is not read: nothing is doubled.
    down = dict(HOSTS[0], up=False)
    assert cephx_lockbox_osds([down], lvs, [L0])[0]["doubled"] == []


def test_lockbox_osds_every_result_read():
    # Q-L5: the result of each host is read once, also where no OSD that is
    # up needs it.
    lvs = {"results": [LVS["results"][0], lvs_result("node-1", "{x")]}
    with pytest.raises(AnsibleFilterError) as e:
        cephx_lockbox_osds(HOSTS[:1], lvs, [])
    assert e.value.message == "lvs on node-1: did not print JSON"


def test_lockbox_osds_host_listed_twice():
    # Q-L5: the loop goes over each host once.
    lvs = {"results": [LVS["results"][0], lvs_result("node-0", report(DB0))]}
    with pytest.raises(AnsibleFilterError) as e:
        cephx_lockbox_osds(HOSTS[:1], lvs, [])
    assert e.value.message == "lvs: node-0 is listed twice"


def test_lockbox_osds_up_without_result():
    # An OSD that is up whose host was not read: the play reads every such
    # host, so this is not "no LVs".
    with pytest.raises(AnsibleFilterError) as e:
        cephx_lockbox_osds(HOSTS[:1], NO_LOOP, [])
    assert e.value.message == "lvs: no result for node-0"


def test_lockbox_osds_nothing():
    assert cephx_lockbox_osds([], NO_LOOP, []) == []
    assert cephx_lockbox_osds([], {"results": []}, []) == []


def test_lockbox_osds_garbage():
    lvs = {
        "results": [lvs_result("node-0", '{"report": [{"lv": [%s' % json.dumps(BLOCK0))]
    }
    with pytest.raises(AnsibleFilterError) as e:
        cephx_lockbox_osds(HOSTS[:1], lvs, [])
    assert e.value.message == "lvs on node-0: did not print JSON"
    assert K0 not in str(e.value)
    lvs = {"results": [lvs_result("node-0", json.dumps({"report": [{"lv": BLOCK0}]}))]}
    with pytest.raises(AnsibleFilterError) as e:
        cephx_lockbox_osds(HOSTS[:1], lvs, [])
    assert e.value.message == "lvs on node-0: an entry of the report has no lv list"
    assert K0 not in str(e.value)


@pytest.mark.parametrize(
    "result, message",
    [
        # failed_when: false: the rc decides (the read refusal stopped the
        # play before; this is the backstop).
        (lvs_result("node-0", HOST, rc=5), "lvs on node-0: failed (rc 5)"),
        (
            lvs_result("node-0", HOST, rc=5, stderr="bad " + K0),
            "lvs on node-0: failed (rc 5)",
        ),
        (
            lvs_result("node-0", HOST, skipped=True),
            "lvs on node-0: the command was skipped",
        ),
        (
            lvs_result("node-0", HOST, unreachable=True),
            "lvs on node-0: the host was unreachable",
        ),
        (lvs_result("node-0", None), "lvs on node-0: stdout is not a str"),
        (lvs_result("node-0", HOST, rc="0"), "lvs on node-0: rc is not an int"),
        ({"rc": 0, "stdout": HOST}, "lvs: a result has no item"),
        (lvs_result(5, HOST), "lvs: an item is not a host name"),
    ],
)
def test_lockbox_osds_bad_result(result, message):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_lockbox_osds(HOSTS[:1], {"results": [result]}, [])
    assert e.value.message == message
    assert K0 not in str(e.value)


@pytest.mark.parametrize("lvs", [{}, {"results": None}, None, "x"])
def test_lockbox_osds_no_loop_result(lvs):
    with pytest.raises(AnsibleFilterError):
        cephx_lockbox_osds([], lvs, [])


# cephx_lockbox_copies

FP_NEW, FP_OLD = "0123456789ab", "ba9876543210"
WANT = {
    "failed": False,
    "changed": False,
    "entity": L0,
    "has_pending": True,
    "in_force_fp": FP_NEW,
}
EXISTS = {"failed": False, "changed": False, "stat": {"exists": True}}
MISSING = {"failed": False, "changed": False, "stat": {"exists": False}}
SKIPPED = {"skipped": True, "changed": False, "false_condition": "x"}


def kr(fp=None, **more):
    """A cephx_keyring result: with a fingerprint, or (failed_when: false)
    the module's failure, its `failed` cleared."""
    out = {"failed": False, "changed": False}
    if fp is not None:
        out["in_force_fp"] = fp
    else:
        out["msg"] = "keyring input: no [entity] header"
    return dict(out, **more)


def tag_key(name, fp=None, **more):
    return dict(kr(fp, **more), item={"name": name, "secret": K0})


def test_copies():
    keys = {"results": [tag_key("a", FP_OLD), tag_key("b", FP_NEW), tag_key("c")]}
    assert cephx_lockbox_copies(keys, EXISTS, kr(FP_NEW), WANT) == {
        "tags": ["a", "c"],
        "file": False,
    }


@pytest.mark.parametrize(
    "file_key, todo",
    [
        (kr(FP_OLD), True),
        # The file cannot be parsed: its key line is written.
        (kr(), True),
        (kr(failed=True), True),
        # Q-L6: a fingerprint that is not one cannot be read: it differs.
        (kr(None, in_force_fp=None), True),
        (kr(""), True),
        (kr(5), True),
        (kr(FP_NEW, failed=True), True),
        (kr(FP_NEW), False),
    ],
)
def test_copies_file(file_key, todo):
    copies = cephx_lockbox_copies({"results": []}, EXISTS, file_key, WANT)
    # Q-L7: a bool.
    assert copies == {"tags": [], "file": todo}
    assert copies["file"] is todo


def test_copies_file_missing():
    # ceph-volume writes a missing file from the tag at the OSD's next start.
    keys = {"results": [tag_key("a")]}
    assert cephx_lockbox_copies(keys, MISSING, SKIPPED, WANT) == {
        "tags": ["a"],
        "file": False,
    }


@pytest.mark.parametrize(
    "want",
    [
        {},
        kr(None),
        kr(""),
        kr(5),
        dict(WANT, in_force_fp=None),
        dict(WANT, failed=True),
        dict(WANT, skipped=True),
        "x",
    ],
)
def test_copies_want_checked_with_nothing_to_compare(want):
    # Q-L6: the wanted fingerprint is checked whatever is compared.
    with pytest.raises(AnsibleFilterError) as e:
        cephx_lockbox_copies({"results": []}, MISSING, SKIPPED, want)
    assert e.value.message.startswith("the lockbox keyring")


def test_null_fingerprints_never_match():
    # Q-L6 (fail-open closed): a missing fingerprint never equals another.
    keys = {"results": [tag_key("a", None, in_force_fp=None)]}
    with pytest.raises(AnsibleFilterError):
        cephx_lockbox_copies(keys, EXISTS, kr(None), dict(WANT, in_force_fp=None))
    copies = cephx_lockbox_copies(keys, EXISTS, kr(None, in_force_fp=None), WANT)
    assert copies == {"tags": ["a"], "file": True}


@pytest.mark.parametrize(
    "keys, stat, file_key, message",
    [
        (
            {"results": [dict(tag_key("a", FP_NEW), skipped=True)]},
            MISSING,
            SKIPPED,
            "the inspection of the tags: a result was skipped",
        ),
        (
            {"results": [dict(tag_key("a", FP_NEW), unreachable=True)]},
            MISSING,
            SKIPPED,
            "the inspection of the tags: a result did not reach its host",
        ),
        (
            {"results": [kr(FP_NEW)]},
            MISSING,
            SKIPPED,
            "the inspection of the tags: a result has no item",
        ),
        ({}, MISSING, SKIPPED, "the inspection of the tags: the result has no results"),
        ({"results": []}, {}, SKIPPED, "the stat of lockbox.keyring has no stat"),
        (
            {"results": []},
            {"stat": {}},
            SKIPPED,
            "the stat of lockbox.keyring: exists is not a bool",
        ),
        (
            {"results": []},
            {"stat": {"exists": 0}},
            SKIPPED,
            "the stat of lockbox.keyring: exists is not a bool",
        ),
        (
            {"results": []},
            dict(EXISTS, failed=True),
            SKIPPED,
            "the stat of lockbox.keyring failed",
        ),
        (
            {"results": []},
            EXISTS,
            SKIPPED,
            "the inspection of lockbox.keyring was skipped",
        ),
        (
            {"results": []},
            EXISTS,
            dict(kr(FP_NEW), unreachable=True),
            "the inspection of lockbox.keyring did not reach its host",
        ),
    ],
)
def test_copies_unexpected(keys, stat, file_key, message):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_lockbox_copies(keys, stat, file_key, WANT)
    assert e.value.message == message


# cephx_lockbox_unwritten

FILE = "/var/lib/ceph/f/osd.0/lockbox.keyring"
TAG_TEXT = (
    "the ceph.cephx_lockbox_secret tag of %s does not carry the new key after"
    " lvchange (lvm reading it from standard input)"
)


def after(name, fp=None, **more):
    return dict(kr(fp, **more), item=name)


def test_unwritten_none():
    tags_after = {"results": [after("a", FP_NEW)]}
    assert cephx_lockbox_unwritten(tags_after, True, kr(FP_NEW), WANT, FILE, "n") == []
    assert cephx_lockbox_unwritten(NO_LOOP, False, SKIPPED, WANT, FILE, "n") == []


def test_unwritten():
    tags_after = {
        "results": [
            after("a", FP_OLD),
            after("b", failed=True),
            after("c"),
            after("d", FP_NEW),
        ]
    }
    assert cephx_lockbox_unwritten(
        tags_after, True, kr(FP_OLD), WANT, FILE, "node-0"
    ) == [
        TAG_TEXT % "a",
        TAG_TEXT % "b",
        TAG_TEXT % "c",
        FILE + " on node-0 does not carry the new key",
    ]


@pytest.mark.parametrize(
    "file_after, text",
    [
        (kr(None, msg="cannot parse"), " (cannot parse)"),
        (kr(None, failed=True, msg=" cannot parse\n"), " (cannot parse)"),
        # Q-L8: the module's message is masked.
        (kr(None, msg="bad key %s" % K0), " (bad key <key>)"),
        # Q-L8 (T-13): an empty or null message is left out.
        (kr(FP_OLD, msg=None), ""),
        (kr(FP_OLD, msg=""), ""),
        (kr(FP_OLD, msg="  "), ""),
        (kr(FP_OLD), ""),
        ({"failed": False, "in_force_fp": None}, ""),
    ],
)
def test_unwritten_file(file_after, text):
    out = cephx_lockbox_unwritten(NO_LOOP, True, file_after, WANT, FILE, "node-0")
    assert out == [FILE + " on node-0 does not carry the new key" + text]
    assert K0 not in repr(out)


def test_unwritten_file_message_not_text():
    with pytest.raises(AnsibleFilterError) as e:
        cephx_lockbox_unwritten(NO_LOOP, True, kr(None, msg=["x"]), WANT, FILE, "n")
    assert e.value.message == (
        "the inspection of the written lockbox.keyring: msg is not a str"
    )


def test_unwritten_file_not_written():
    assert cephx_lockbox_unwritten(NO_LOOP, False, SKIPPED, WANT, FILE, "n") == []


@pytest.mark.parametrize("want", [{}, kr(None), dict(WANT, in_force_fp="")])
def test_unwritten_want_checked_with_nothing_to_compare(want):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_lockbox_unwritten(NO_LOOP, False, SKIPPED, want, FILE, "h")
    assert e.value.message.startswith("the lockbox keyring")


@pytest.mark.parametrize(
    "tags_after, todo, file_after",
    [
        # Q-L7: file_todo is a bool (the play passes `| bool`).
        (NO_LOOP, "True", kr(FP_NEW)),
        (NO_LOOP, 1, kr(FP_NEW)),
        (NO_LOOP, None, SKIPPED),
        # The file was to be written but was not read again.
        (NO_LOOP, True, SKIPPED),
        (NO_LOOP, True, dict(kr(FP_NEW), unreachable=True)),
        ({"results": [kr(FP_NEW)]}, False, SKIPPED),
        ({"results": [dict(after("a", FP_NEW), skipped=True)]}, False, SKIPPED),
        ({}, False, SKIPPED),
    ],
)
def test_unwritten_unexpected(tags_after, todo, file_after):
    with pytest.raises(AnsibleFilterError):
        cephx_lockbox_unwritten(tags_after, todo, file_after, WANT, FILE, "h")


# cephx_lockbox_get_refusal

ENTITY = {"name": L0, "osd": 0, "host": "node-0"}


def get(rc=0, stdout="", stderr="", **more):
    return dict({"rc": rc, "stdout": stdout, "stderr": stderr, "failed": False}, **more)


@pytest.mark.parametrize(
    "result, text",
    [
        (SKIPPED, ""),
        (get(stdout="[%s]\n\tkey = %s" % (L0, K0)), ""),
        (get(stdout="[%s]" % L0, skipped=False), ""),
        (
            get(stdout="[client.osd-lockbox.%s]" % U1),
            "did not return the keyring of the entity",
        ),
        (get(), "did not return the keyring of the entity"),
        (get(stdout=" [%s]" % L0), "did not return the keyring of the entity"),
        (get(2, stderr="Error ENOENT: boom\n"), "failed (rc 2): Error ENOENT: boom"),
        (get(1, stderr="bad " + K0), "failed (rc 1): bad <key>"),
        # Q-L9: stderr null or missing is empty (T-4: no ": ").
        (get(1, stderr=None), "failed (rc 1)"),
        ({"rc": 1, "stdout": "", "failed": False}, "failed (rc 1)"),
        (get(1, stderr=""), "failed (rc 1)"),
        # failed_when: false cleared failed; the rc decides.
        (get(0, stdout="[%s]" % L0, failed=True), ""),
    ],
)
def test_get_refusal(result, text):
    expected = "ceph auth get %s %s." % (L0, text) if text else ""
    assert cephx_lockbox_get_refusal(result, ENTITY) == expected


@pytest.mark.parametrize(
    "result, message",
    [
        # Q-L9: rc is an int.
        (get("0", stdout="[%s]" % L0), "ceph auth get %s: rc is not an int" % L0),
        (get(True, stdout="[%s]" % L0), "ceph auth get %s: rc is not an int" % L0),
        (
            {"rc": 0, "stdout_lines": []},
            "ceph auth get %s: the result has no stdout" % L0,
        ),
        ({"stdout": ""}, "ceph auth get %s: the result has no rc" % L0),
        (get(0, stdout=None), "ceph auth get %s: stdout is not a str" % L0),
        (get(1, stderr=5), "ceph auth get %s: stderr is not a str" % L0),
        (get(0, unreachable=True), "ceph auth get %s: the host was unreachable" % L0),
    ],
)
def test_get_refusal_unexpected(result, message):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_lockbox_get_refusal(result, ENTITY)
    assert e.value.message == message


# cephx_lockbox_done


def done(action, written, restarted, commit):
    return {
        "name": L0,
        "class": "lockbox",
        "action": action,
        "osd": 0,
        "host": "node-0",
        "written": written,
        "restarted": restarted,
        "commit": commit,
    }


@pytest.mark.parametrize(
    "now, commit",
    [
        (SKIPPED, ""),
        (dict(WANT, has_pending=False), "start"),
        (dict(WANT, has_pending=True), "play"),
        (dict(WANT, has_pending=True, skipped=False), "play"),
    ],
)
def test_done(now, commit):
    out = cephx_lockbox_done(ENTITY, "staged", ["ceph-0/osd-block-0"], True, now)
    assert out == done("staged", ["ceph-0/osd-block-0"], True, commit)


@pytest.mark.parametrize(
    "now",
    [
        # Q-L10: has_pending is a bool, as the module returns it.
        dict(WANT, has_pending="yes"),
        dict(WANT, has_pending="True"),
        dict(WANT, has_pending=1),
        dict(WANT, has_pending=None),
        {"failed": False},
        dict(WANT, failed=True),
        dict(WANT, unreachable=True),
        "x",
    ],
)
def test_done_unexpected(now):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_lockbox_done(ENTITY, "staged", [], False, now)
    assert e.value.message.startswith("the keyring read after the restart")


def test_commit_follows_the_checked_done():
    # _rotate-keys-lockbox.yml commits the key only as cephx_lockbox_done
    # decides (commit "play"), from a task before the commit: a has_pending
    # that is not a bool stops there (test_done_unexpected), before any
    # ceph auth commit-pending.
    import yaml

    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "..",
        "playbooks",
        "ceph",
        "tasks",
        "_rotate-keys-lockbox.yml",
    )
    with open(path) as f:
        tasks = yaml.safe_load(f)
    decide = next(i for i, t in enumerate(tasks) if "cephx_lockbox_done" in str(t))
    commit = next(
        i
        for i, t in enumerate(tasks)
        if "commit-pending" in str(t.get("ansible.builtin.command", ""))
    )
    assert decide < commit
    when = tasks[commit]["when"]
    assert "has_pending" not in str(when)
    assert when == "_rotate_keys_lockbox_done.commit == 'play'"


# The OSD map around the restart of one OSD (_restart-osd.yml)


def dump(*osds, rc=0, stderr="", stdout=None):
    """The registered result of `ceph osd dump -f json`."""
    if stdout is None:
        stdout = json.dumps({"epoch": 40, "osds": list(osds)})
    return {"rc": rc, "stdout": stdout, "stderr": stderr, "failed": False}


def entry(osd, up=1, up_from=10):
    return {"osd": osd, "uuid": "u%d" % osd, "up": up, "up_from": up_from}


def test_osd_state():
    d = dump(entry(0, up=1, up_from=12), entry(1, up=0, up_from=7))
    assert cephx_osd_state(d, "0") == {"up": True, "up_from": 12}
    assert cephx_osd_state(d, 1) == {"up": False, "up_from": 7}


def test_osd_state_not_listed():
    assert cephx_osd_state(dump(entry(0)), "3") == {}
    assert cephx_osd_state(dump(), "0") == {}


@pytest.mark.parametrize(
    "osds, message",
    [
        # up is exactly 0 or 1: JSON's true is not 1, of any OSD
        ([entry(0, up=True)], "ceph osd dump: up is not 0 or 1"),
        ([entry(0), entry(1, up=False)], "ceph osd dump: up is not 0 or 1"),
        ([entry(0, up=2)], "ceph osd dump: up is not 0 or 1"),
        ([entry(0, up="1")], "ceph osd dump: up is not 0 or 1"),
        ([entry(0, up=1.0)], "ceph osd dump: up is not 0 or 1"),
        ([entry(0, up_from=True)], "ceph osd dump: up_from is not an int"),
        ([entry(0, up_from="12")], "ceph osd dump: up_from is not an int"),
        ([entry(0), entry(0)], "ceph osd dump: an OSD is listed twice"),
        ([{"osd": 0, "up_from": 1}], "ceph osd dump: an entry of osds has no up"),
        ([{"osd": 0, "up": 1}], "ceph osd dump: an entry of osds has no up_from"),
        ([{"osd": True, "up": 1, "up_from": 1}], "ceph osd dump: osd is not an int"),
        (["x"], "ceph osd dump: an entry of osds is not an object"),
    ],
)
def test_osd_state_refused(osds, message):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_osd_state(dump(*osds), "0")
    assert str(e.value) == message


@pytest.mark.parametrize(
    "stdout, message",
    [
        ("{", "ceph osd dump: did not print JSON"),
        ("[]", "ceph osd dump: did not print a JSON object"),
        ('{"osds": {}}', "ceph osd dump: osds is not a list"),
    ],
)
def test_osd_state_garbage(stdout, message):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_osd_state(dump(stdout=stdout), "0")
    assert str(e.value) == message


@pytest.mark.parametrize("osd_id", [None, True, "x", "-1", -1])
def test_osd_state_id_refused(osd_id):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_osd_state(dump(entry(0)), osd_id)
    assert str(e.value) == "ceph osd dump: the OSD id is not a number"


def test_osd_back():
    # Back: up, with an up_from newer than before the restart.
    assert cephx_osd_back(dump(entry(0, up=1, up_from=13)), "0", 12) is True
    assert cephx_osd_back(dump(entry(0, up=1, up_from=12)), "0", 12) is False
    assert cephx_osd_back(dump(entry(0, up=0, up_from=13)), "0", 12) is False


def test_osd_back_not_yet():
    # A command that failed, an answer that is not JSON and an OSD missing
    # from the map count as "not yet".
    assert cephx_osd_back(dump(rc=1, stdout="", stderr="EAGAIN"), "0", 12) is False
    assert cephx_osd_back(dump(stdout="Error: timed out"), "0", 12) is False
    assert cephx_osd_back(dump(stdout=""), "0", 12) is False
    assert cephx_osd_back(dump(entry(1, up_from=13)), "0", 12) is False


@pytest.mark.parametrize(
    "result, message",
    [
        (dump(entry(0, up=True, up_from=13)), "ceph osd dump: up is not 0 or 1"),
        (dump(entry(0, up_from=13.0)), "ceph osd dump: up_from is not an int"),
        (dump(stdout="[]"), "ceph osd dump: did not print a JSON object"),
        ({"rc": True, "stdout": "{}"}, "ceph osd dump: rc is not an int"),
        ({"skipped": True}, "ceph osd dump: the command was skipped"),
    ],
)
def test_osd_back_refused(result, message):
    # An answer that cannot be judged stops after the wait, readably; the
    # wait's own check ends the wait on it (its task is no_log).
    with pytest.raises(AnsibleFilterError) as e:
        cephx_osd_back(result, "0", 12)
    assert str(e.value) == message
    assert cephx_osd_back_until(result, "0", 12) is True


@pytest.mark.parametrize("up_from", [None, True, "12", 12.0])
def test_osd_back_up_from_refused(up_from):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_osd_back(dump(entry(0, up_from=13)), "0", up_from)
    assert str(e.value) == "cephx_osd_back: up_from is not an int"


def test_osd_back_until():
    assert cephx_osd_back_until(dump(entry(0, up_from=13)), "0", 12) is True
    assert cephx_osd_back_until(dump(entry(0, up_from=12)), "0", 12) is False
    assert cephx_osd_back_until(dump(rc=1, stdout=""), "0", 12) is False
