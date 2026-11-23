import json
import os

import pytest
import yaml
from ansible.errors import AnsibleFilterError
from ansible.utils.unsafe_proxy import AnsibleUnsafeText

from cephx_rotate_texts import (
    FilterModule,
    cephx_rotate_failure,
    cephx_rotate_summary,
)

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "rotate_texts")
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

OV = "/tmp/pt/cfg/environments/kolla/files/overlays"
INF = "/tmp/pt/cfg/environments/infrastructure/files/ceph"
CHECKOUT = {
    "client.glance": [OV + "/glance/ceph.client.glance.keyring"],
    "client.cinder": [
        OV + "/cinder/cinder-volume/ceph.client.cinder.keyring",
        OV + "/cinder/cinder-backup/ceph.client.cinder.keyring",
        OV + "/nova/ceph.client.cinder.keyring",
    ],
    "client.nova": [OV + "/nova/ceph.client.nova.keyring"],
    "client.gnocchi": [OV + "/gnocchi/ceph.client.gnocchi.keyring"],
    "client.cinder-backup": [
        OV + "/cinder/cinder-backup/ceph.client.cinder-backup.keyring"
    ],
    "client.admin": [INF + "/ceph.client.admin.keyring"],
}
HOURS = (
    "no new key: the active key is younger than 24 hours "
    "(ceph_rotate_keys_min_age; 0 rotates again)"
)
AGAIN = (
    "Run the same command again: an entity staged in this run keeps its "
    "pending key (or, once committed, gets no new key before "
    "ceph_rotate_keys_min_age), and its files are written again; an entity "
    "rotated in this run gets no new key before ceph_rotate_keys_min_age, and "
    "each of its daemons that does not run with its key is redeployed."
)
AGAIN_MIN_AGE_0 = (
    "Run the command again, but without -e ceph_rotate_keys_min_age=0: with "
    "it, every entity rotated or committed in this run would get a new key "
    "again. Without it (the default, 24 hours): an entity staged in this run "
    "keeps its pending key (or, once committed, gets no new key), and its "
    "files are written again; an entity rotated in this run gets no new key, "
    "and each of its daemons that does not run with its key is redeployed."
)


def services():
    with open(os.path.join(ROOT, "playbooks", "ceph", "vars", "cephx-keys.yml")) as f:
        return yaml.safe_load(f)["_cephx_key_services"]


def fixture(case):
    """The texts of a pall case: {summary: [lines], failure: text}."""
    out, part = {}, None
    with open(os.path.join(FIXTURES, case + ".txt")) as f:
        for line in f.read().splitlines():
            if line in ("summary:", "failure:"):
                part = line[:-1]
                out[part] = [] if part == "summary" else None
            elif part == "summary":
                out["summary"].append(json.loads(line))
            else:
                out["failure"] = json.loads(line)
    return out


def staged(name, action="staged"):
    return {
        "name": name,
        "class": "admin" if name == "client.admin" else "openstack",
        "action": action,
        "checkout": CHECKOUT[name],
        "monitors": name != "client.admin",
    }


def rotated(name, cls, action="rotated", redeployed=(), kept=()):
    return {
        "name": name,
        "class": cls,
        "action": action,
        "checkout": [],
        "monitors": False,
        "redeployed": list(redeployed),
        "kept": list(kept),
    }


def crash(n, action="rotated"):
    return rotated("client.crash.node-%d" % n, "crash", action, ["crash.node-%d" % n])


def sctx(min_age=24):
    return {
        "min_age": min_age,
        "mons": ["localhost"],
        "services": services(),
        "now": "<TIME>",
    }


def fctx(min_age=24):
    return {"min_age": min_age}


def current(**kw):
    c = {
        "name": "",
        "group": {},
        "results": [],
        "redeployed": [],
        "action": "",
    }
    c.update(kw)
    return c


RGW0 = "client.rgw.default.node-0.abc"
RGW1 = "client.rgw.default.node-1.xyz"
OK_KW = [
    "client.cinder-backup",
    "client.cinder",
    "client.glance",
    "client.gnocchi",
    "client.nova",
]

SUMMARIES = {
    "sg": ([staged("client.glance")], 24),
    "rc": ([staged("client.glance", "skipped_recent")], 24),
    "cn": ([staged("client.cinder"), staged("client.nova")], 24),
    "cnc": (
        [
            staged("client.cinder", "skipped_recent"),
            staged("client.nova", "skipped_recent"),
        ],
        24,
    ),
    "mf2": (
        [staged("client.cinder", "already_staged"), staged("client.nova")],
        24,
    ),
    "ad": ([staged("client.admin")], 24),
    "ok-kw": ([staged(n) for n in OK_KW], 24),
    "crash": ([crash(0), crash(1)], 24),
    "rgw": (
        [
            rotated(RGW0, "rgw", redeployed=["rgw.default.node-0.abc"]),
            rotated(RGW1, "rgw", redeployed=["rgw.default.node-1.xyz"]),
        ],
        24,
    ),
    "skip": (
        [
            crash(0, "skipped_recent"),
            crash(1, "skipped_recent"),
            rotated(RGW0, "rgw", "skipped_recent", kept=["rgw.default.node-0.abc"]),
            rotated(
                RGW1, "rgw", "skipped_recent", redeployed=["rgw.default.node-1.xyz"]
            ),
        ],
        1000,
    ),
    "hang2": (
        [
            rotated(
                RGW0, "rgw", "skipped_recent", redeployed=["rgw.default.node-0.abc"]
            ),
            rotated(RGW1, "rgw", redeployed=["rgw.default.node-1.xyz"]),
        ],
        24,
    ),
    "mix": (
        [
            staged("client.cinder", "skipped_recent"),
            staged("client.nova", "skipped_recent"),
            staged("client.gnocchi"),
        ],
        24,
    ),
    "mixr": (
        [
            rotated("client.bootstrap-osd", "bootstrap"),
            rotated("client.bootstrap-rgw", "bootstrap"),
            staged("client.glance"),
        ],
        24,
    ),
}


@pytest.mark.parametrize("case", sorted(SUMMARIES))
def test_summary_matches_the_run(case):
    done, min_age = SUMMARIES[case]
    assert cephx_rotate_summary(done, sctx(min_age)) == fixture(case)["summary"]


def _crash_group():
    return {
        "names": ["client.crash.node-0", "client.crash.node-1"],
        "class": "crash",
        "daemons": [
            {
                "daemon": "crash.node-0",
                "host": "localhost",
                "entity": "client.crash.node-0",
            },
            {
                "daemon": "crash.node-1",
                "host": "localhost",
                "entity": "client.crash.node-1",
            },
        ],
        "one_at_a_time": False,
    }


def _crash_current():
    return current(
        name="client.crash.node-0, client.crash.node-1",
        group=_crash_group(),
        results=[
            {"name": "client.crash.node-0", "action": "rotated"},
            {"name": "client.crash.node-1", "action": "rotated"},
        ],
    )


FAILURES = {
    "hang": (
        [],
        current(
            name=RGW0,
            group={
                "names": [RGW0],
                "class": "rgw",
                "daemons": [
                    {
                        "daemon": "rgw.default.node-0.abc",
                        "host": "localhost",
                        "entity": RGW0,
                    }
                ],
                "one_at_a_time": True,
            },
            results=[{"name": RGW0, "action": "rotated"}],
        ),
        fctx(),
    ),
    "mf": (
        [staged("client.cinder")],
        current(name="client.nova"),
        fctx(),
    ),
    "rdf": ([], _crash_current(), fctx()),
    "rdz": ([], _crash_current(), fctx(min_age=0)),
}


@pytest.mark.parametrize("case", sorted(FAILURES))
def test_failure_matches_the_run(case):
    done, cur, ctx = FAILURES[case]
    assert cephx_rotate_failure(done, cur, ctx) == fixture(case)["failure"]


# The failure message as plain sentences: single spaces, no line break
# (the default callback shows a line break as a literal \\n), no space at
# either end.


def plain(text):
    assert "  " not in text
    assert "\n" not in text
    assert text == text.strip()
    return text


def test_failure_whole_text_staged_then_in_progress():
    # T-1, example mf.
    done, cur, ctx = FAILURES["mf"]
    assert plain(cephx_rotate_failure(done, cur, ctx)) == (
        "The run stopped at client.nova (see the error above)."
        " client.cinder: staged, written to the checkout and the monitor hosts."
        " client.nova: not finished (its key may have been staged). " + AGAIN
    )


def test_failure_whole_text_group():
    # T-1, example rdf.
    done, cur, ctx = FAILURES["rdf"]
    assert plain(cephx_rotate_failure(done, cur, ctx)) == (
        "The run stopped at client.crash.node-0, client.crash.node-1 (see the"
        " error above). client.crash.node-0, client.crash.node-1: not finished"
        " (client.crash.node-0: rotated, client.crash.node-1: rotated;"
        " redeployed: none of crash.node-0, crash.node-1). " + AGAIN
    )


def test_failure_whole_text_min_age_zero():
    done, cur, ctx = FAILURES["rdz"]
    assert plain(cephx_rotate_failure(done, cur, ctx)) == (
        "The run stopped at client.crash.node-0, client.crash.node-1 (see the"
        " error above). client.crash.node-0, client.crash.node-1: not finished"
        " (client.crash.node-0: rotated, client.crash.node-1: rotated;"
        " redeployed: none of crash.node-0, crash.node-1). " + AGAIN_MIN_AGE_0
    )


def test_failure_whole_text_rgw_one_at_a_time():
    done, cur, ctx = FAILURES["hang"]
    assert plain(cephx_rotate_failure(done, cur, ctx)) == (
        "The run stopped at " + RGW0 + " (see the error above). " + RGW0 + ":"
        " not finished (" + RGW0 + ": rotated; redeployed: none of"
        " rgw.default.node-0.abc). " + AGAIN
    )


def test_failure_records_of_each_class():
    # T-1b: a staged entry whose key was not renewed says "no new key", as
    # the other classes do.
    done = [
        staged("client.glance", "skipped_recent"),
        dict(staged("client.admin", "already_staged")),
        rotated(RGW0, "rgw", "skipped_recent", ["a", "b"], ["c"]),
        rotated("client.bootstrap-osd", "bootstrap"),
    ]
    out = cephx_rotate_failure(done, current(), fctx())
    assert plain(out) == (
        "The run stopped at an entity (see the error above)."
        " client.glance: no new key, written to the checkout and the monitor"
        " hosts."
        " client.admin: already staged, written to the checkout."
        " " + RGW0 + ": no new key; redeployed: a, b; running with this key,"
        " not redeployed: c."
        " client.bootstrap-osd: rotated. " + AGAIN
    )


def test_failure_between_entities():
    out = cephx_rotate_failure([], current(), fctx())
    assert plain(out) == "The run stopped at an entity (see the error above). " + AGAIN


def test_failure_current_with_action():
    out = cephx_rotate_failure(
        [], current(name="client.glance", action="already_staged"), fctx()
    )
    assert plain(out) == (
        "The run stopped at client.glance (see the error above). client.glance:"
        " not finished (already staged, its files not all written). " + AGAIN
    )


def test_failure_group_without_actions_or_daemons():
    g = {"names": ["client.bootstrap-osd"], "class": "bootstrap", "daemons": []}
    out = cephx_rotate_failure(
        [],
        current(
            name="client.bootstrap-osd",
            group=g,
            results=[{"name": "x", "action": "rotated"}],
        ),
        fctx(),
    )
    assert plain(out) == (
        "The run stopped at client.bootstrap-osd (see the error above)."
        " client.bootstrap-osd: not finished (no key rotated). " + AGAIN
    )


def test_failure_group_actions_and_redeployed():
    g = _crash_group()
    cur = _crash_current()
    cur["results"] = [
        {"name": "client.crash.node-1", "action": "skipped_recent"},
        {"name": "client.other", "action": "rotated"},
    ]
    cur["redeployed"] = ["crash.node-1"]
    cur["group"] = g
    out = cephx_rotate_failure([], cur, fctx())
    assert plain(out) == (
        "The run stopped at client.crash.node-0, client.crash.node-1 (see the"
        " error above). client.crash.node-0, client.crash.node-1: not finished"
        " (client.crash.node-1: no new key; redeployed: crash.node-1 of"
        " crash.node-0, crash.node-1). " + AGAIN
    )


def test_failure_unknown_class_raises():
    d = dict(staged("client.glance"), **{"class": "other"})
    with pytest.raises(AnsibleFilterError) as e:
        cephx_rotate_failure([d], current(), fctx())
    assert str(e.value) == "cephx_rotate_failure: an entry of an unknown class"


def test_failure_unknown_action_raises():
    d = staged("client.glance", "renamed")
    with pytest.raises(AnsibleFilterError) as e:
        FilterModule().filters()["cephx_rotate_failure"]([d], current(), fctx())
    assert str(e.value) == "cephx_rotate_failure: unexpected input (KeyError)"


def test_failure_missing_field_raises_without_the_value():
    d = staged("client.glance")
    del d["monitors"]
    with pytest.raises(AnsibleFilterError) as e:
        FilterModule().filters()["cephx_rotate_failure"]([d], current(), fctx())
    assert str(e.value) == "cephx_rotate_failure: unexpected input (KeyError)"


def test_failure_unsafe_text():
    done, cur, ctx = FAILURES["mf"]
    out = cephx_rotate_failure(
        [staged(AnsibleUnsafeText("client.cinder"))],
        current(name=AnsibleUnsafeText("client.nova")),
        fctx(),
    )
    assert out == cephx_rotate_failure(done, cur, ctx)
    assert type(out) is str


# The summary: the branches no pall case reaches, with their whole texts.


def test_summary_admin_already_in_force():
    out = cephx_rotate_summary([staged("client.admin", "skipped_recent")], sctx())
    assert out == [
        "client.admin: " + HOURS + "; its files were written again with that key"
        " (see the next steps)",
        "  checkout: " + INF + "/ceph.client.admin.keyring",
        "Next steps, if the repository or the services do not have this key yet"
        " (whoever still holds the old key cannot open new connections), now and"
        " one directly after the other:",
        "1. Copy the keyring files listed under checkout above from the manager's"
        " checkout into your configuration repository (encrypt them first if your"
        " repository keeps keyrings encrypted), commit, push, then: osism apply"
        " configuration",
        "2. osism apply cephclient.",
        "3. osism validate ceph-keys",
        "client.admin: its new key is already in force. If the manager's ceph"
        " fails with the old key: osism apply cephclient installs the keyring"
        " from the checkout.",
    ]


def test_summary_unmapped_entity_and_no_service():
    # T-5: step 2 reads as a sentence when no service is mapped.
    d = dict(staged("client.glance"), name="client.site", checkout=[])
    out = cephx_rotate_summary([d], sctx())
    assert out == [
        "client.site: staged",
        "  monitors: /etc/ceph/ceph.client.site.keyring on localhost",
        "Next steps, now and one directly after the other (staged keys are not"
        " left lying around):",
        "1. Copy the keyring files listed under checkout above from the manager's"
        " checkout into your configuration repository (encrypt them first if your"
        " repository keeps keyrings encrypted), commit, push, then: osism apply"
        " configuration",
        "2. Apply the services that use client.site. The first use of a new key"
        " commits it.",
        "3. osism validate ceph-keys",
        "Do not use the staged keyring by hand (no test login with it): its first"
        " use commits it, and so does any failed login for the entity with a"
        " wrong key. From the commit on, the old key stops working, and whoever"
        " still holds it cannot open new connections until it is applied.",
    ]


def test_summary_unmapped_after_mapped():
    d = dict(staged("client.glance"), name="client.site", checkout=[])
    out = cephx_rotate_summary([staged("client.glance"), d], sctx())
    assert (
        "2. osism apply glance and the services that use client.site. The first"
        " use of a new key commits it." in out
    )


def test_summary_services_deduplicated_in_order():
    out = cephx_rotate_summary(
        [staged("client.nova"), staged("client.admin"), staged("client.cinder")],
        sctx(),
    )
    assert (
        "2. osism apply cinder, then osism apply nova, then osism apply"
        " cephclient. The first use of a new key commits it." in out
    )


def test_summary_monitors_joined():
    ctx = dict(sctx(), mons=["mon-0", "mon-1"])
    out = cephx_rotate_summary([staged("client.glance")], ctx)
    assert out[2] == "  monitors: /etc/ceph/ceph.client.glance.keyring on mon-0, mon-1"


def test_summary_unknown_class_raises():
    # Q-T8: an unknown class is a bug in the play, not a staged key.
    d = dict(staged("client.glance"), **{"class": "other"})
    with pytest.raises(AnsibleFilterError) as e:
        cephx_rotate_summary([d], sctx())
    assert str(e.value) == "cephx_rotate_summary: an entry of an unknown class"


@pytest.mark.parametrize(
    "d",
    [
        staged("client.glance", "renamed"),
        staged("client.glance", "rotated"),
        crash(0, "renamed"),
        crash(0, "staged"),
        crash(0, "already_staged"),
    ],
)
def test_summary_unknown_action_raises(d):
    # An action that _set-entity-key.yml does not give for the entry's
    # class is a bug in the play, not a key younger than min_age.
    with pytest.raises(AnsibleFilterError) as e:
        FilterModule().filters()["cephx_rotate_summary"]([d], sctx())
    assert str(e.value) == "cephx_rotate_summary: unexpected input (KeyError)"


def test_summary_kept_after_redeployed():
    d = rotated(RGW0, "rgw", redeployed=["a"], kept=["b", "c"])
    assert cephx_rotate_summary([d], sctx()) == [
        RGW0 + ": rotated",
        "  redeployed: a",
        "  running with this key, not redeployed: b, c",
        RGW0 + ": nothing else to do (these keys never leave Ceph). Check: osism"
        " validate ceph-keys",
    ]


def test_summary_min_age_as_a_number():
    # T-8: the play hands min_age over as an int (checked by the input
    # checks), so "0024" reads 24.
    out = cephx_rotate_summary([crash(0, "skipped_recent")], sctx(24))
    assert out[0] == (
        "client.crash.node-0: no new key: the active key is younger than 24"
        " hours (ceph_rotate_keys_min_age; 0 rotates again)"
    )


def test_summary_unsafe_text():
    d = staged(AnsibleUnsafeText("client.glance"), AnsibleUnsafeText("staged"))
    out = cephx_rotate_summary([d], sctx())
    assert out[0] == "client.glance: staged"
    assert all(type(x) is str for x in out)


def test_summary_missing_field_raises_without_the_value():
    d = staged("client.glance")
    del d["checkout"]
    with pytest.raises(AnsibleFilterError) as e:
        FilterModule().filters()["cephx_rotate_summary"]([d], sctx())
    assert str(e.value) == "cephx_rotate_summary: unexpected input (KeyError)"


def test_key_services_shape():
    # Q-T9: the services per entity are a static vars file, checked here
    # once: each entity names a list of services.
    s = services()
    assert isinstance(s, dict) and s
    for name, svcs in s.items():
        assert isinstance(name, str) and name.startswith("client.")
        assert isinstance(svcs, list) and svcs
        assert all(isinstance(x, str) and x for x in svcs)


def test_filter_module():
    assert {k: f.__wrapped__ for k, f in FilterModule().filters().items()} == {
        "cephx_rotate_failure": cephx_rotate_failure,
        "cephx_rotate_summary": cephx_rotate_summary,
    }
