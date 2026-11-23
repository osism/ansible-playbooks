import json

import pytest
from ansible.errors import AnsibleFilterError

from cephx_rotate import (
    FilterModule,
    cephx_daemons,
    cephx_rotate_class_refusal,
    cephx_rotate_classes_asked,
    cephx_rotate_classify,
    cephx_rotate_host_refusal,
    cephx_rotate_input_refusal,
    cephx_rotate_min_age,
    cephx_rotate_openstack_names,
    cephx_rotate_plan,
    cephx_rotate_read_refusal,
    cephx_rotate_skipped,
    cephx_rotate_tokens,
)

KEYWORDS = {
    "openstack": "the OpenStack keys",
    "crash": "the keys of the crash daemons",
    "rgw": "the keys of the RGW daemons",
    "bootstrap": "the client.bootstrap-* keys",
}
OPENSTACK_KEYS = [
    "client.cinder-backup",
    "client.cinder",
    "client.glance",
    "client.gnocchi",
    "client.nova",
    "client.manila",
]
U0 = "aaaaaaaa-0000-4000-8000-000000000000"
U1 = "bbbbbbbb-1111-4111-8111-111111111111"
L0 = "client.osd-lockbox." + U0
L1 = "client.osd-lockbox." + U1
EXISTING = [
    "client.glance",
    "client.cinder",
    "client.nova",
    "client.cinder-backup",
    "client.gnocchi",
    "client.admin",
    "client.crash.node-0",
    "client.crash.node-1",
    "client.crash.gone",
    "client.rgw.default.node-0.abc",
    "client.rgw.default.node-1.xyz",
    "client.rgw.old",
    "client.bootstrap-osd",
    "client.bootstrap-rgw",
    "client.osd-lockbox.f00",
    L0,
    L1,
    "osd.0",
    "mgr.x",
    "mon.",
    "mds.fs.a",
]
DAEMONS = [
    {
        "daemon": "crash.node-0",
        "host": "node-0",
        "entity": "client.crash.node-0",
        "class": "crash",
    },
    {
        "daemon": "crash.node-1",
        "host": "node-1",
        "entity": "client.crash.node-1",
        "class": "crash",
    },
    {
        "daemon": "rgw.default.node-0.abc",
        "host": "node-0",
        "entity": "client.rgw.default.node-0.abc",
        "class": "rgw",
    },
    {
        "daemon": "rgw.default.node-1.xyz",
        "host": "node-1",
        "entity": "client.rgw.default.node-1.xyz",
        "class": "rgw",
    },
]


def ctx(tokens, **over):
    c = {
        "tokens": tokens,
        "openstack_keys": OPENSTACK_KEYS,
        "existing": EXISTING,
        "pending": [],
        "daemons": DAEMONS,
        "keywords": KEYWORDS,
        "configuration_directory": "/opt/configuration",
    }
    c.update(over)
    return c


def classify(tokens, **over):
    c = ctx(tokens, **over)
    return cephx_rotate_classify(tokens, c), c


def refusal(tokens, **over):
    classified, c = classify(tokens, **over)
    return cephx_rotate_class_refusal(classified, c)


def test_filters_registered():
    assert set(FilterModule().filters()) == {
        "cephx_rotate_tokens",
        "cephx_rotate_input_refusal",
        "cephx_rotate_min_age",
        "cephx_rotate_classes_asked",
        "cephx_rotate_openstack_names",
        "cephx_rotate_read_refusal",
        "cephx_rotate_classify",
        "cephx_rotate_skipped",
        "cephx_rotate_class_refusal",
        "cephx_rotate_plan",
        "cephx_rotate_host_refusal",
        "cephx_daemons",
    }


# openstack_keys


def test_openstack_names():
    assert cephx_rotate_openstack_names(
        [{"name": "client.glance", "mode": "0600"}, {"name": "client.nova"}]
    ) == ["client.glance", "client.nova"]
    assert cephx_rotate_openstack_names([]) == []


@pytest.mark.parametrize("openstack_keys", [None, "client.x", {"name": "client.x"}])
def test_openstack_names_not_a_list(openstack_keys):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_rotate_openstack_names(openstack_keys)
    assert str(e.value) == "openstack_keys is not a list"


@pytest.mark.parametrize(
    "openstack_keys", [[{"key": "client.x"}], ["client.x"], [None], [{"name": 1}]]
)
def test_openstack_names_entry_without_name(openstack_keys):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_rotate_openstack_names(openstack_keys)
    assert str(e.value) == "openstack_keys: an entry has no name"


# Tokens and input


def test_tokens_comma_string():
    assert cephx_rotate_tokens(" client.cinder, client.nova ,,") == [
        "client.cinder",
        "client.nova",
    ]


def test_tokens_list():
    assert cephx_rotate_tokens([" client.glance", " ", "crash "]) == [
        "client.glance",
        "crash",
    ]
    assert cephx_rotate_tokens("") == []
    assert cephx_rotate_tokens([]) == []


@pytest.mark.parametrize(
    "value, tokens",
    [
        # An entry that is not a str is not a name: kept as '', which the
        # input check counts (a number or a bool is never a name meant).
        (["client.glance", 5, True, None, {"a": 1}], ["client.glance"] + [""] * 4),
        # A value that is neither a str nor a list: one entry, not a name.
        (7, [""]),
        (True, [""]),
        ({"client.glance": "x"}, [""]),
        (("client.glance",), [""]),
    ],
)
def test_tokens_other_entries_are_not_names(value, tokens):
    assert cephx_rotate_tokens(value) == tokens


def test_tokens_bool_entry_refused_as_not_a_name():
    tokens = cephx_rotate_tokens([True])
    assert cephx_rotate_input_refusal(tokens, 24) == bad_names(1, "is")


def bad_names(n, verb):
    return (
        "ceph_rotate_keys takes entity names and keywords only, for example"
        " ceph_rotate_keys=client.glance or ceph_rotate_keys=client.cinder,client.nova;"
        " %d of its entries %s not (not shown, in case it is a key). Keys are"
        " generated by the monitors; this play takes none. Nothing was changed."
        % (n, verb)
    )


def test_input_entries_not_names():
    assert cephx_rotate_input_refusal(["client.glance", "a:b+c="], 24) == bad_names(
        1, "is"
    )
    assert cephx_rotate_input_refusal(["x=", "", "y/"], 24) == bad_names(3, "are")


def test_input_no_entries():
    assert cephx_rotate_input_refusal([], 24) == (
        "Set ceph_rotate_keys to the entities to rotate, for example osism apply"
        " cephadm-rotate-keys -e ceph_rotate_keys=client.glance. Nothing was changed."
    )


KEY = "AQ" + "D" + "k" * 35 + "=="
LONGER = "a longer value (not shown, in case it is a key)"


@pytest.mark.parametrize(
    "value, shown",
    [
        (False, "false"),
        (True, "true"),
        (-1, "-1"),
        (1.5, "1.5"),
        (24.0, "24.0"),
        ("1.5", '"1.5"'),
        ("x", '"x"'),
        ("1d", '"1d"'),
        ("-1", '"-1"'),
        (" 24", '" 24"'),
        ("24\n", '"24\\n"'),
        ("", '""'),
        (None, "null"),
        ([24], "[24]"),
        ("x" * 22, '"%s"' % ("x" * 22)),
        # A longer value is not shown: a key given by mistake, also glued to
        # characters the key mask would not separate it from.
        ("x" * 23, LONGER),
        (KEY, LONGER),
        ("24," + KEY, LONGER),
        ("1/" + KEY, LONGER),
        ("x" + KEY, LONGER),
        (KEY[:-2], LONGER),
        # Digits beyond what an hour count needs (int() refuses over 4300).
        ("1" * 10, '"1111111111"'),
        ("1" * 5000, LONGER),
    ],
)
def test_min_age_values_refused(value, shown):
    assert cephx_rotate_input_refusal(["client.glance"], value) == (
        "ceph_rotate_keys_min_age is a number of hours (default 24; 0 disables"
        " the check), not %s. Nothing was changed." % shown
    )
    with pytest.raises(AnsibleFilterError) as e:
        cephx_rotate_min_age(value)
    assert str(e.value) == "ceph_rotate_keys_min_age is not a number of hours"


@pytest.mark.parametrize(
    "value, hours",
    [
        (0, 0),
        (24, 24),
        ("24", 24),
        ("0", 0),
        ("48", 48),
        ("0024", 24),
        ("9" * 9, 999999999),
    ],
)
def test_min_age_values_accepted(value, hours):
    assert cephx_rotate_input_refusal(["client.glance"], value) == ""
    got = cephx_rotate_min_age(value)
    assert got == hours and type(got) is int


def test_min_age_reaches_the_summary_as_a_number():
    from cephx_rotate_texts import cephx_rotate_summary

    done = {
        "name": "client.crash.node-0",
        "class": "crash",
        "action": "skipped_recent",
        "checkout": [],
        "monitors": False,
        "redeployed": [],
        "kept": ["crash.node-0"],
    }
    sctx = {"min_age": cephx_rotate_min_age("0024"), "mons": [], "services": {}}
    sctx["now"] = "<TIME>"
    assert cephx_rotate_summary([done], sctx)[0] == (
        "client.crash.node-0: no new key: the active key is younger than 24"
        " hours (ceph_rotate_keys_min_age; 0 rotates again)"
    )


def test_input_refusal_order():
    # Not names before none before min_age.
    assert cephx_rotate_input_refusal(["a+b"], "x") == bad_names(1, "is")
    assert cephx_rotate_input_refusal([], "x").startswith("Set ceph_rotate_keys")


def test_classes_asked():
    assert cephx_rotate_classes_asked(["client.glance"]) == []
    assert cephx_rotate_classes_asked(["rgw", "client.crash.node-0"]) == [
        "crash",
        "rgw",
    ]
    assert cephx_rotate_classes_asked([L0, "bootstrap"]) == [
        "bootstrap",
        "lockbox",
    ]


# The cluster reads

# The registered result of a loop over no items.
NO_ITEMS = {
    "changed": False,
    "results": [],
    "skipped": True,
    "skipped_reason": "No items in the list",
}


def test_read_auth_export():
    ok = {"rc": 0, "stdout": ' {"auth": []}', "stderr": ""}
    assert cephx_rotate_read_refusal("auth_export", ok) == ""
    assert cephx_rotate_read_refusal("auth_export", {"rc": 0, "stdout": "[]"}) == ""
    assert cephx_rotate_read_refusal("auth_export", {"rc": 0, "stdout": "oops"}) == (
        "ceph auth export failed to print JSON. Nothing was changed."
    )
    key = "AQ" + "B" + "x" * 35 + "=="
    failed = {"rc": 22, "stdout": "", "stderr": "Error EINVAL: bad key " + key}
    assert cephx_rotate_read_refusal("auth_export", failed) == (
        "ceph auth export failed (rc 22): Error EINVAL: bad key <key>. Nothing was changed."
    )
    # failed_when: false clears failed; with failed true, rc decides as well.
    failed = dict(failed, failed=True)
    assert cephx_rotate_read_refusal("auth_export", failed).startswith(
        "ceph auth export failed (rc 22)"
    )


def test_read_orch_ps():
    reg = {
        "results": [
            {"item": "crash", "rc": 22, "stdout": "", "stderr": "nope\n"},
            {"item": "rgw", "rc": 0, "stdout": "{}"},
        ]
    }
    assert cephx_rotate_read_refusal("orch_ps", reg) == (
        "ceph orch ps --daemon-type crash failed (rc 22): nope."
        " ceph orch ps --daemon-type rgw did not print JSON. Nothing was changed."
    )
    assert (
        cephx_rotate_read_refusal(
            "orch_ps", {"results": [{"item": "crash", "rc": 0, "stdout": "[]"}]}
        )
        == ""
    )
    assert cephx_rotate_read_refusal("orch_ps", NO_ITEMS) == ""
    # A failed command without stderr, or with blanks only.
    for stderr in ({}, {"stderr": ""}, {"stderr": None}, {"stderr": " \n"}):
        r = dict({"item": "rgw", "rc": 1, "stdout": ""}, **stderr)
        assert cephx_rotate_read_refusal("orch_ps", {"results": [r]}) == (
            "ceph orch ps --daemon-type rgw failed (rc 1). Nothing was changed."
        )


@pytest.mark.parametrize(
    "name, result, message",
    [
        ("auth_export", {"stdout": "[]"}, "ceph auth export: the result has no rc"),
        ("auth_export", {"rc": 0}, "ceph auth export: the result has no stdout"),
        (
            "auth_export",
            {"rc": "0", "stdout": "[]"},
            "ceph auth export: rc is not an int",
        ),
        (
            "auth_export",
            {"rc": 0, "stdout": None},
            "ceph auth export: stdout is not a str",
        ),
        ("auth_export", {"skipped": True}, "ceph auth export: the command was skipped"),
        (
            "auth_export",
            {"rc": True, "stdout": "{}"},
            "ceph auth export: rc is not an int",
        ),
        ("auth_export", "x", "ceph auth export: the result is not a mapping"),
        ("orch_ps", "x", "ceph orch ps: the result is not a mapping"),
        ("orch_ps", {"skipped": True}, "ceph orch ps: the result has no results"),
        (
            "orch_ps",
            {"results": [{"rc": 0, "stdout": "[]"}]},
            "ceph orch ps: a result has no item",
        ),
        (
            "orch_ps",
            {"results": [{"item": "crash", "skipped": True}]},
            "ceph orch ps --daemon-type crash: the command was skipped",
        ),
        ("orch_ps", {"results": "x"}, "ceph orch ps: the results are not a list"),
        ("nope", {}, "cephx_rotate_read_refusal: no read nope"),
    ],
)
def test_read_unexpected_results_fail_closed(name, result, message):
    # A result of an unexpected shape stops the play: the filter raises,
    # naming the command, never the result.
    with pytest.raises(AnsibleFilterError) as e:
        cephx_rotate_read_refusal(name, result)
    assert str(e.value) == message


def test_read_error_message_has_no_input():
    key = "AQ" + "C" + "y" * 35 + "=="
    with pytest.raises(AnsibleFilterError) as e:
        cephx_rotate_read_refusal("auth_export", {"rc": 0, "stdoutx": key})
    assert key not in str(e.value)


# Classification


def names(classified):
    return [(c["name"], c["class"], c["keyword"]) for c in classified]


def test_classify_names():
    assert names(
        classify(
            [
                "client.admin",
                "client.glance",
                "client.crash.node-0",
                "osd.0",
                "client.foo",
            ]
        )[0]
    ) == [
        ("client.admin", "admin", ""),
        ("client.glance", "openstack", ""),
        ("client.crash.node-0", "crash", ""),
        ("osd.0", "daemon", ""),
        ("client.foo", "unknown", ""),
    ]


def test_classify_openstack_skips_absent_keys():
    classified, c = classify(["openstack"])
    assert names(classified) == [
        (n, "openstack", "openstack")
        for n in [
            "client.cinder-backup",
            "client.cinder",
            "client.glance",
            "client.gnocchi",
            "client.nova",
        ]
    ]
    assert cephx_rotate_skipped(["openstack"], c) == ["client.manila"]
    assert cephx_rotate_skipped(["client.glance"], c) == []


def test_classify_openstack_keys_of_other_classes():
    # client.admin and entries of other classes in openstack_keys are not
    # OpenStack keys.
    keys = ["client.glance", "client.admin", "client.crash.x", "client.osd-lockbox.y"]
    classified, c = classify(["openstack", "client.crash.x"], openstack_keys=keys)
    assert names(classified) == [
        ("client.glance", "openstack", "openstack"),
        ("client.crash.x", "crash", ""),
    ]


def test_classify_crash_rgw_bootstrap():
    assert names(classify(["crash", "rgw", "bootstrap"])[0]) == [
        ("client.crash.node-0", "crash", "crash"),
        ("client.crash.node-1", "crash", "crash"),
        ("client.rgw.default.node-0.abc", "rgw", "rgw"),
        ("client.rgw.default.node-1.xyz", "rgw", "rgw"),
        ("client.bootstrap-osd", "bootstrap", "bootstrap"),
        ("client.bootstrap-rgw", "bootstrap", "bootstrap"),
    ]


def test_classify_crash_daemons_share_a_key():
    daemons = DAEMONS + [dict(DAEMONS[0], daemon="crash.other")]
    assert names(classify(["crash"], daemons=daemons)[0]) == [
        ("client.crash.node-0", "crash", "crash"),
        ("client.crash.node-1", "crash", "crash"),
    ]


def test_classify_lockbox_not_handled():
    # The keyword of a class not handled stays one entry of its class.
    assert names(classify(["lockbox", L1])[0]) == [
        ("lockbox", "lockbox", "lockbox"),
        (L1, "lockbox", ""),
    ]


def test_class_refusal_none():
    assert refusal(["client.cinder", "client.nova", "crash", "bootstrap"]) == ""


def test_refuse_ceph_daemons():
    assert refusal(["mon.", "mgr.x", "client.glance", "osd.0"]) == (
        "mon., mgr.x, osd.0: the keys of Ceph daemons (mon., mgr.*, osd.*, mds.*) are"
        " rotated by cephadm's upgrade, not by this play. Nothing was changed."
    )


def test_refuse_unknown():
    assert refusal(["client.unknown", "client.manila-share-x"]) == (
        "client.unknown, client.manila-share-x: not a key this play rotates. It takes"
        " the keywords openstack, crash, rgw and bootstrap, the entries of"
        " openstack_keys (client.cinder-backup, client.cinder, client.glance,"
        " client.gnocchi, client.nova, client.manila), client.admin, client.crash.*,"
        " client.rgw.* and client.bootstrap-*. Tenant keys (Manila) are rotated"
        " through Manila's access rules. Nothing was changed."
    )


def test_refuse_not_handled():
    assert refusal(["lockbox", "client.glance", L1]) == (
        "lockbox, %s: not handled by this play (classes lockbox). Nothing was"
        " changed." % L1
    )


@pytest.mark.parametrize(
    "tokens, text",
    [
        (["client.glance", "client.glance"], "client.glance"),
        (
            ["openstack", "client.glance"],
            "client.glance (the keyword openstack includes the OpenStack keys)",
        ),
        (
            ["bootstrap", "bootstrap"],
            "bootstrap, client.bootstrap-osd, client.bootstrap-rgw"
            " (the keyword bootstrap includes the client.bootstrap-* keys)",
        ),
        (
            ["client.glance", "rgw", "crash", "client.glance"],
            "client.glance (the keyword crash includes the keys of the crash daemons;"
            " the keyword rgw includes the keys of the RGW daemons)",
        ),
    ],
)
def test_refuse_twice(tokens, text):
    assert refusal(tokens) == (
        "ceph_rotate_keys names an entity more than once: %s. Nothing was changed."
        % text
    )


CINDER_ALONE = (
    "client.cinder and client.nova must be rotated together"
    " (ceph_rotate_keys=client.cinder,client.nova): Nova uses both, and every"
    " running guest is migrated after their rotation. Nothing was changed."
)


@pytest.mark.parametrize(
    "tokens", [["client.cinder"], ["client.nova", "client.glance"]]
)
def test_refuse_cinder_without_nova(tokens):
    assert refusal(tokens) == CINDER_ALONE


def test_cinder_and_nova_through_openstack():
    assert refusal(["openstack"]) == ""
    # client.nova missing from the cluster: the keyword skips it, client.cinder
    # stays alone.
    existing = [e for e in EXISTING if e != "client.nova"]
    assert refusal(["openstack"], existing=existing) == CINDER_ALONE


def test_refuse_daemon_keys_without_daemon():
    assert refusal(["client.crash.gone", "client.rgw.old", "client.crash.node-0"]) == (
        "client.crash.gone: no crash daemon uses it; client.rgw.old: no RGW daemon"
        " uses it (ceph orch ps). A key no daemon uses is deleted (ceph auth del"
        " <name>), not rotated. Nothing was changed."
    )


def test_refuse_missing():
    assert refusal(["client.rgw.default.node-9.q", "client.bootstrap-x"]) == (
        "client.rgw.default.node-9.q, client.bootstrap-x: does not exist on the"
        " cluster (ceph auth export). This play gives existing entities new keys;"
        " cephadm-pools creates the keys of openstack_keys. Nothing was changed."
    )


def test_refuse_pending():
    pending = ["client.crash.node-1", "client.glance", "client.bootstrap-rgw"]
    text = (
        ": %s (ceph auth export), staged outside this play, which rotates the keys"
        " of crash, RGW and bootstrap without staging. Rotating would discard it."
        " Decide for each: ceph auth commit-pending <name> puts the pending key in"
        " force, ceph auth clear-pending <name> drops it; then run the command"
        " again. Nothing was changed."
    )
    assert refusal(["crash", "client.glance"], pending=pending) == (
        "client.crash.node-1" + text % "has a pending key"
    )
    assert refusal(["crash", "bootstrap"], pending=pending) == (
        "client.crash.node-1, client.bootstrap-rgw" + text % "have pending keys"
    )
    # A staged key with a pending key is not refused.
    assert refusal(["client.glance"], pending=pending) == ""


def test_refusal_order():
    # Each pair: two refusals of the stage apply, the earlier in the play's
    # order wins with its own text.
    assert refusal(["client.foo", "osd.0"]).startswith(
        "osd.0: the keys of Ceph daemons"
    )
    assert refusal(["client.foo", "client.foo"]).startswith(
        "client.foo, client.foo: not a key"
    )
    assert refusal([L0, "client.nope.x"]).startswith("client.nope.x: not a key")
    assert refusal(["client.glance", "client.glance", "lockbox"]).startswith(
        "lockbox: not handled"
    )
    assert refusal(["client.cinder", "client.cinder"]).startswith(
        "ceph_rotate_keys names an entity more than once"
    )
    assert refusal(["client.cinder", "client.crash.gone"]) == CINDER_ALONE
    assert refusal(["client.crash.gone", "client.rgw.nope"]).startswith(
        "client.crash.gone: no crash daemon"
    )
    assert refusal(
        ["client.rgw.nope", "client.crash.node-0"], pending=["client.crash.node-0"]
    ).startswith("client.rgw.nope: does not exist")


# The plan


def test_plan_shapes():
    classified, c = classify(
        ["client.glance", "client.admin", "crash", "rgw", "bootstrap"]
    )
    plan = cephx_rotate_plan(classified, c)
    assert plan["entities"] == [
        {"name": "client.glance", "class": "openstack"},
        {"name": "client.admin", "class": "admin"},
        {"name": "client.crash.node-0", "class": "crash"},
        {"name": "client.crash.node-1", "class": "crash"},
        {"name": "client.rgw.default.node-0.abc", "class": "rgw"},
        {"name": "client.rgw.default.node-1.xyz", "class": "rgw"},
        {"name": "client.bootstrap-osd", "class": "bootstrap"},
        {"name": "client.bootstrap-rgw", "class": "bootstrap"},
    ]
    assert plan["staged"] == plan["entities"][:2]
    assert plan["groups"] == [
        {
            "names": ["client.crash.node-0", "client.crash.node-1"],
            "class": "crash",
            "one_at_a_time": False,
            "daemons": DAEMONS[:2],
        },
        {
            "names": ["client.rgw.default.node-0.abc"],
            "class": "rgw",
            "one_at_a_time": True,
            "daemons": [DAEMONS[2]],
        },
        {
            "names": ["client.rgw.default.node-1.xyz"],
            "class": "rgw",
            "one_at_a_time": True,
            "daemons": [DAEMONS[3]],
        },
        {
            "names": ["client.bootstrap-osd", "client.bootstrap-rgw"],
            "class": "bootstrap",
            "one_at_a_time": False,
            "daemons": [],
        },
    ]


def test_plan_empty():
    assert cephx_rotate_plan([], ctx([])) == {
        "entities": [],
        "staged": [],
        "groups": [],
    }


# Stage 3


def stat(item, exists=True, isdir=True, writeable=True):
    return {
        "item": item,
        "stat": {"exists": exists, "isdir": isdir, "writeable": writeable},
    }


def test_host_monitors():
    reg = {
        "results": [
            stat("mon-0"),
            stat("mon-1", writeable=False),
            stat("mon-2", isdir=False),
            stat("mon-3", exists=False),
            {"item": "mon-4", "skipped": True},
            {
                "item": "mon-5",
                "skipped": False,
                "stat": {"exists": True, "isdir": False},
            },
        ]
    }
    # Not a directory first, then not writable; a missing /etc/ceph is fine.
    # Only a skipped result is passed over (mon-4), not one with skipped
    # false (mon-5).
    assert cephx_rotate_host_refusal("monitors", reg, {}) == (
        "/etc/ceph is not a writable directory on mon-2, mon-5, mon-1."
        " Nothing was changed."
    )
    assert cephx_rotate_host_refusal("monitors", {"results": [stat("mon-0")]}, {}) == ""
    assert cephx_rotate_host_refusal("monitors", NO_ITEMS, {}) == ""
    # The task skipped (no OpenStack key in the plan): each item skipped.
    skipped = {"skipped": True, "results": [{"item": "mon-0", "skipped": True}]}
    assert cephx_rotate_host_refusal("monitors", skipped, {}) == ""


@pytest.mark.parametrize(
    "result, message",
    [
        ({}, "the monitor hosts: the result has no results"),
        ({"results": [{"item": "mon-0"}]}, "the monitor hosts: the result has no stat"),
        (
            {"results": [{"item": "mon-0", "stat": {"isdir": True}}]},
            "the monitor hosts: the stat has no exists",
        ),
        (
            {"results": [{"item": "mon-0", "stat": {"exists": True, "isdir": 1}}]},
            "the monitor hosts: the stat's isdir is not a bool",
        ),
        (
            {"results": [{"item": "mon-0", "stat": {"exists": True, "isdir": True}}]},
            "the monitor hosts: the stat has no writeable",
        ),
        (
            {"results": [dict(stat("mon-0"), failed=True)]},
            "the monitor hosts: the stat failed",
        ),
        (
            {"results": [dict(stat("mon-0"), skipped="yes")]},
            "a registered result's skipped is not a bool",
        ),
    ],
)
def test_host_monitors_unexpected_results_fail_closed(result, message):
    with pytest.raises(AnsibleFilterError) as e:
        cephx_rotate_host_refusal("monitors", result, {})
    assert str(e.value) == message


def test_host_fsid():
    fsid = "00000000-1111-2222-3333-444444444444"
    assert cephx_rotate_host_refusal("fsid", {"rc": 0, "stdout": fsid + "\n"}, {}) == ""
    assert cephx_rotate_host_refusal("fsid", {"skipped": True}, {}) == ""
    assert cephx_rotate_host_refusal("fsid", {"rc": 0, "stdout": "nope"}, {}) == (
        "ceph fsid did not print an fsid. Nothing was changed."
    )
    assert cephx_rotate_host_refusal(
        "fsid", {"rc": 1, "stdout": "", "stderr": "x"}, {}
    ) == ("ceph fsid failed (rc 1): x. Nothing was changed.")
    assert cephx_rotate_host_refusal(
        "fsid", {"rc": 1, "stdout": "", "stderr": ""}, {}
    ) == ("ceph fsid failed (rc 1). Nothing was changed.")
    with pytest.raises(AnsibleFilterError, match="^ceph fsid: the result has no rc$"):
        cephx_rotate_host_refusal("fsid", {"stdout": fsid}, {})


def test_host_configuration_directory():
    staged = [{"name": "client.glance", "class": "openstack"}]
    assert cephx_rotate_host_refusal(
        "configuration_directory", {"staged": staged, "defined": False}, {}
    ) == (
        "configuration_directory (the manager's checkout of the configuration"
        " repository) is not set. Nothing was changed."
    )
    assert (
        cephx_rotate_host_refusal(
            "configuration_directory", {"staged": staged, "defined": True}, {}
        )
        == ""
    )
    assert (
        cephx_rotate_host_refusal(
            "configuration_directory", {"staged": [], "defined": False}, {}
        )
        == ""
    )


def test_host_checkout_places():
    staged = [
        {"name": "client.gnocchi", "class": "openstack"},
        {"name": "client.glance", "class": "openstack"},
    ]
    checked = [
        {
            "name": "client.glance",
            "dest": "/c/glance/ceph.client.glance.keyring",
            "exists": True,
            "writeable": True,
        }
    ]
    text = (
        "client.gnocchi: no directory for its keyring in the configuration"
        " repository's checkout (%s; copy-ceph-keys writes to the same places,"
        " ceph_custom_keys adds more). If the service is not run, delete the key"
        " (ceph auth del <name>) instead of rotating it. Nothing was changed."
    )
    result = {"staged": staged, "checked": checked}
    assert cephx_rotate_host_refusal(
        "checkout_places", result, {"configuration_directory": "/tmp/pt/nocfg"}
    ) == (text % "/tmp/pt/nocfg")
    # A null configuration_directory never gets here: the check of
    # configuration_directory refuses it first (the play passes `defined`
    # false for null).
    assert (
        cephx_rotate_host_refusal(
            "checkout_places", {"staged": staged[1:], "checked": checked}, {}
        )
        == ""
    )


def test_host_checkout_writable():
    def c(dest, exists=True, writeable=True):
        return {"name": "x", "dest": dest, "exists": exists, "writeable": writeable}

    checked = [
        c("/c/a/k1"),
        c("/c/b/k1", writeable=False),
        c("/c/b/k2", writeable=False),
        c("/c/d/k1", exists=False, writeable=False),
        c("/c/d/k2", exists=False, writeable=False),
    ]
    # The missing directories first, then those not writable; each once.
    assert cephx_rotate_host_refusal("checkout_writable", checked, {}) == (
        "/c/d, /c/b cannot be written (a directory for the keyrings in"
        " the checkout). Nothing was changed."
    )
    assert cephx_rotate_host_refusal("checkout_writable", [c("/c/a/k")], {}) == ""
    assert cephx_rotate_host_refusal("checkout_writable", [], {}) == ""


def _without(entries, i, key):
    out = [dict(e) for e in entries]
    del out[i][key]
    return out


FILTERS = FilterModule().filters()


@pytest.mark.parametrize(
    "name, args",
    [
        # The play's facts, built by these filters, are read as they are: a
        # field missing is a bug in the play, stopped by the filter's guard.
        (
            "cephx_rotate_class_refusal",
            lambda: (
                classify(["crash"])[0],
                ctx(["crash"], daemons=_without(DAEMONS, 0, "entity")),
            ),
        ),
        (
            "cephx_rotate_class_refusal",
            lambda: ([{"name": "client.glance"}], ctx([])),
        ),
        ("cephx_rotate_plan", lambda: ([{"class": "crash"}], ctx([]))),
        (
            "cephx_rotate_host_refusal",
            lambda: (
                "checkout_places",
                {"staged": [{"class": "openstack"}], "checked": []},
                {},
            ),
        ),
        (
            "cephx_rotate_host_refusal",
            lambda: ("checkout_writable", [{"dest": "/c/a/k", "exists": True}], {}),
        ),
        (
            "cephx_rotate_host_refusal",
            lambda: ("checkout_writable", [{"exists": False, "writeable": True}], {}),
        ),
    ],
)
def test_facts_missing_fields_fail_closed(name, args):
    with pytest.raises(AnsibleFilterError) as e:
        FILTERS[name](*args())
    assert str(e.value) == name + ": unexpected input (KeyError)"


def test_host_unknown_check():
    with pytest.raises(AnsibleFilterError, match="no check nope"):
        cephx_rotate_host_refusal("nope", {}, {})


# The daemons (cluster reads)


def orch_ps(**by_type):
    return {
        "results": [
            {"item": t, "rc": 0, "stdout": json.dumps(entries)}
            for t, entries in by_type.items()
        ]
    }


def test_daemons():
    reg = orch_ps(
        crash=[
            {"daemon_name": "crash.node-0", "hostname": "node-0", "x": 1},
            {"daemon_name": "crash.node-1", "hostname": "node-1"},
        ],
        rgw=[{"daemon_name": "rgw.default.node-0.abc", "hostname": "node-0"}],
    )
    assert cephx_daemons(reg) == DAEMONS[:3]


def test_daemons_none_listed():
    assert cephx_daemons(orch_ps(crash=[], rgw=[])) == []
    assert cephx_daemons(NO_ITEMS) == []


@pytest.mark.parametrize(
    "stdout, message",
    [
        ('[{"daemon_name": "crash.a"}]', "an entry has no hostname"),
        ('[{"hostname": "h"}]', "an entry has no daemon_name"),
        ('[{"daemon_name": null, "hostname": "h"}]', "daemon_name is not a str"),
        ('[{"daemon_name": "crash.a", "hostname": null}]', "hostname is not a str"),
        ('[{"daemon_name": "", "hostname": "h"}]', "an entry's daemon_name is empty"),
        (
            '[{"daemon_name": "crash.a", "hostname": ""}]',
            "an entry's hostname is empty",
        ),
        ('["crash.a"]', "an entry is not an object"),
        ('{"daemon_name": "crash.a", "hostname": "h"}', "did not print a JSON list"),
        (
            '[{"daemon_name": "crash.a", "hostname": "h"},'
            ' {"daemon_name": "crash.a", "hostname": "h"}]',
            "crash.a is listed twice",
        ),
        ("[not json AQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", "did not print JSON"),
    ],
)
def test_daemons_unexpected_output_fails_closed(stdout, message):
    reg = {"results": [{"item": "crash", "rc": 0, "stdout": stdout}]}
    with pytest.raises(AnsibleFilterError) as e:
        cephx_daemons(reg)
    assert str(e.value) == "ceph orch ps --daemon-type crash: " + message


def test_daemons_listed_twice_across_types_stops():
    one = [{"daemon_name": "crash.a", "hostname": "h"}]
    with pytest.raises(AnsibleFilterError) as e:
        cephx_daemons(orch_ps(crash=one, rgw=one))
    assert str(e.value) == "ceph orch ps --daemon-type rgw: crash.a is listed twice"


@pytest.mark.parametrize("reg", [{}, {"results": [{"item": "crash", "rc": 0}]}])
def test_daemons_unexpected_results_fail_closed(reg):
    with pytest.raises(AnsibleFilterError):
        cephx_daemons(reg)


# The host status of the daemon hosts (stage 3)


def hosts(*entries, rc=0, stderr=""):
    return {"rc": rc, "stdout": json.dumps(list(entries)), "stderr": stderr}


def host_status(result, daemons=DAEMONS):
    return cephx_rotate_host_refusal(
        "host_status", {"hosts": result, "daemons": daemons}, {}
    )


AGAIN = " Run the command again when the host is online."


def test_host_status_offline_and_maintenance():
    reg = hosts(
        {"hostname": "node-0", "status": "Offline"},
        {"hostname": "node-1", "status": "maintenance"},
        {"hostname": "node-2", "status": "offline"},
    )
    assert host_status(reg) == (
        "node-0 is offline (ceph orch host ls): cephadm cannot redeploy"
        " crash.node-0, rgw.default.node-0.abc there." + AGAIN + " node-1 is in"
        " maintenance (ceph orch host ls): cephadm cannot redeploy crash.node-1,"
        " rgw.default.node-1.xyz there." + AGAIN + " Nothing was changed."
    )


@pytest.mark.parametrize("status", ["OFFLINE", "offline", "Offline"])
def test_host_status_offline_any_case(status):
    reg = hosts({"hostname": "node-0", "status": status})
    assert host_status(reg, DAEMONS[:1]) == (
        "node-0 is offline (ceph orch host ls): cephadm cannot redeploy"
        " crash.node-0 there." + AGAIN + " Nothing was changed."
    )


@pytest.mark.parametrize("status", ["Maintenance", "MAINTENANCE", "maintenance"])
def test_host_status_maintenance_any_case(status):
    reg = hosts({"hostname": "node-0", "status": status})
    assert host_status(reg, DAEMONS[:1]) == (
        "node-0 is in maintenance (ceph orch host ls): cephadm cannot redeploy"
        " crash.node-0 there." + AGAIN + " Nothing was changed."
    )


def test_host_status_online():
    # Status "" is online; so is any other status.
    reg = hosts(
        {"hostname": "node-0", "status": ""},
        {"hostname": "node-1", "status": "online"},
    )
    assert host_status(reg) == ""
    assert host_status(hosts()) == ""


def test_host_status_other_hosts_ignored():
    reg = hosts({"hostname": "node-9", "status": "offline"})
    assert host_status(reg) == ""


def test_host_status_skipped():
    assert host_status({"skipped": True, "changed": False}, []) == ""


def test_host_status_command_failed():
    reg = {
        "rc": 1,
        "stdout": "",
        "stderr": "key AQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n",
    }
    assert host_status(reg) == (
        "ceph orch host ls failed (rc 1): key <key>. Nothing was changed."
    )
    assert host_status({"rc": 2, "stdout": ""}) == (
        "ceph orch host ls failed (rc 2). Nothing was changed."
    )
    for stdout in ("", " {}", "nope"):
        assert host_status({"rc": 0, "stdout": stdout}) == (
            "ceph orch host ls did not print JSON. Nothing was changed."
        )


@pytest.mark.parametrize(
    "reg, message",
    [
        (hosts({"status": "offline"}), "ceph orch host ls: an entry has no hostname"),
        (hosts({"hostname": "node-0"}), "ceph orch host ls: an entry has no status"),
        (
            hosts({"hostname": "node-0", "status": None}),
            "ceph orch host ls: status is not a str",
        ),
        (
            hosts({"hostname": None, "status": ""}),
            "ceph orch host ls: hostname is not a str",
        ),
        (hosts("node-0"), "ceph orch host ls: an entry is not an object"),
        (
            hosts(
                {"hostname": "node-0", "status": ""},
                {"hostname": "node-0", "status": "offline"},
            ),
            "ceph orch host ls: a host is listed twice",
        ),
        ({"rc": 0, "stdout": "[not json"}, "ceph orch host ls: did not print JSON"),
        ({"stdout": "[]"}, "ceph orch host ls: the result has no rc"),
        ({"rc": 0}, "ceph orch host ls: the result has no stdout"),
    ],
)
def test_host_status_unexpected_output_fails_closed(reg, message):
    # Every entry is checked, also of hosts without daemons to redeploy.
    with pytest.raises(AnsibleFilterError) as e:
        host_status(reg, DAEMONS[:1])
    assert str(e.value) == message
