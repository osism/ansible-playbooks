"""The lockbox keys of encrypted OSDs: their LV tags and their copies.

An encrypted OSD keeps its lockbox key in the ceph.cephx_lockbox_secret tag
of its logical volumes (those tagged ceph.osd_id=<id> and
ceph.osd_fsid=<osd_fsid>) and in lockbox.keyring.

One parser reads `lvs --reportformat json -o vg_name,lv_name,lv_tags`
({"report": [{"lv": [{vg_name, lv_name, lv_tags}]}]}). An LV with one
ceph.cephx_lockbox_secret tag has that secret ('' when the tag is empty: not
encrypted); an LV with more than one is ambiguous (ceph-volume never writes
two) and is named, never read. cephx_osd_lvs gives the LVs of one OSD with
their secrets: it is the one filter that returns keys, and is called only in
no_log tasks. cephx_lockbox_doubled gives the names of that OSD's LVs with
two tags, cephx_lockbox_two_tags the stop that names them (shown outside
no_log), and cephx_lockbox_osds tells cephadm-rotate-keys which OSDs are
encrypted; none of them returns a key. The others serve _sync-lockbox.yml
(which copies to write, which were not written) and _rotate-keys-lockbox.yml
(the keyring read after the restart, what was done). cephx_osd_state,
cephx_osd_back and cephx_osd_back_until read the OSD map for
_restart-osd.yml.

The input is checked as cephx_common says; the lvs output and the
keyrings carry keys. A cephx_keyring result without a fingerprint is a
keyring that cannot be read (failed_when: false clears `failed`).
"""

import importlib.util
import json
import os
import re
import sys
from collections.abc import Mapping

from ansible.errors import AnsibleFilterError


def _load_common():
    # cephx_common.py by its path, as its docstring explains.
    name = "_cephx_common"
    if name not in sys.modules:
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "cephx_common.py"
        )
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        sys.modules[name] = module
    return sys.modules[name]


_common = _load_common()
_guarded = _common._guarded
_cmd = _common._cmd
_is = _common._is
_keyring_of = _common._keyring_of
_loop = _common._loop
_osd_map = _common._osd_map
_osds_up = _common._osds_up
_read = _common._read
_records = _common._records
_state = _common._state
cephx_mask = _common.cephx_mask

SECRET_TAG = "ceph.cephx_lockbox_secret="
# An OSD id as the play passes it through an include's vars (text).
DIGITS = re.compile(r"[0-9]{1,9}")


# The lvs output


def _lvs(stdout, what):
    """The LVs of the lvs output: [(vg, lv, tags, secrets)], secrets being
    the values of the LV's ceph.cephx_lockbox_secret tags."""
    parsed = _records(stdout, what, dict, {"report": list})
    out, seen = [], set()
    for entry in parsed["report"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("lv"), list):
            raise AnsibleFilterError("%s: an entry of the report has no lv list" % what)
        for lv in entry["lv"]:
            if not isinstance(lv, dict):
                raise AnsibleFilterError("%s: an LV is not an object" % what)
            for field in ("vg_name", "lv_name", "lv_tags"):
                if field not in lv:
                    raise AnsibleFilterError("%s: an LV has no %s" % (what, field))
                if not isinstance(lv[field], str):
                    raise AnsibleFilterError(
                        "%s: an LV's %s is not a str" % (what, field)
                    )
            name = (lv["vg_name"], lv["lv_name"])
            if name in seen:
                raise AnsibleFilterError("%s: an LV is listed twice" % what)
            seen.add(name)
            tags = lv["lv_tags"].split(",")
            secrets = [t[len(SECRET_TAG) :] for t in tags if t.startswith(SECRET_TAG)]
            out.append((lv["vg_name"], lv["lv_name"], tags, secrets))
    return out


def _osd_id(value, what):
    """An OSD id: an int, or the play's text of one."""
    if _is(value, int) and value >= 0:
        return value
    if isinstance(value, str) and DIGITS.fullmatch(value):
        return int(value)
    raise AnsibleFilterError("%s: the OSD id is not a number" % what)


def _of_osd(lvs, osd_id, osd_fsid):
    """The LVs tagged ceph.osd_id=<osd_id> and ceph.osd_fsid=<osd_fsid>."""
    mine = ("ceph.osd_id=%d" % osd_id, "ceph.osd_fsid=" + osd_fsid)
    return [lv for lv in lvs if all(t in lv[2] for t in mine)]


def _lv_shown(vg, lv):
    """vg/lv, each name masked: the name is shown, and lvs output is not
    checked for keys elsewhere."""
    return cephx_mask(vg) + "/" + cephx_mask(lv)


def _osd_lvs(lvs_stdout, osd_id, osd_fsid):
    what = "lvs"
    osd_id = _osd_id(osd_id, what)
    if not isinstance(osd_fsid, str) or not osd_fsid:
        raise AnsibleFilterError("%s: the osd_fsid is not a non-empty str" % what)
    return _of_osd(_lvs(lvs_stdout, what), osd_id, osd_fsid)


def cephx_osd_lvs(lvs_stdout, osd_id, osd_fsid):
    """The LVs of osd.<osd_id> with that osd_fsid in the lvs output:
    [{name: vg/lv, secret}], secret being the value of the LV's one
    ceph.cephx_lockbox_secret tag ('' without one, and with more than one:
    cephx_lockbox_doubled names those). Carries the keys: call it only in
    no_log tasks."""
    return [
        {"name": vg + "/" + lv, "secret": secrets[0] if len(secrets) == 1 else ""}
        for vg, lv, _, secrets in _osd_lvs(lvs_stdout, osd_id, osd_fsid)
    ]


def cephx_lockbox_doubled(lvs_stdout, osd_id, osd_fsid):
    """The names (vg/lv, masked) of the LVs of osd.<osd_id> with that
    osd_fsid that have more than one ceph.cephx_lockbox_secret tag. No
    keys, but it reads the lvs output: call it in no_log tasks, and show
    what it returns from another task (cephx_lockbox_two_tags)."""
    return [
        _lv_shown(vg, lv)
        for vg, lv, _, secrets in _osd_lvs(lvs_stdout, osd_id, osd_fsid)
        if len(secrets) > 1
    ]


def cephx_lockbox_two_tags(doubled, osd, written):
    """The stop for LVs of osd.<osd> with two ceph.cephx_lockbox_secret
    tags (doubled, from cephx_lockbox_doubled), found by _sync-lockbox.yml
    before its writes (written empty) or in its read after them (written:
    the copies it wrote, LV names and lockbox.keyring). '' without such
    LVs."""
    if not isinstance(doubled, list) or not isinstance(written, list):
        raise AnsibleFilterError("cephx_lockbox_two_tags: not a list")
    if not doubled:
        return ""
    where = "Two ceph.cephx_lockbox_secret tags on %s (osd.%s)" % (
        ", ".join(doubled),
        osd,
    )
    check = (
        "Check the host's LVM (lvs -o lv_name,lv_tags): each LV of osd.%s needs"
        " one ceph.cephx_lockbox_secret tag, with the key in force next." % osd
    )
    if not written:
        return (
            "%s: refused. Which copy is in force is not known: no copy was"
            " written, and osd.%s is not restarted. %s" % (where, osd, check)
        )
    copies = ", ".join(
        w if w == "lockbox.keyring" else "the tag of " + w for w in written
    )
    return (
        "%s after the writes (written: %s). Which copy is in force is not"
        " known, so osd.%s is not restarted; its new lockbox key is not in"
        " force yet (the old key still works). %s" % (where, copies, osd, check)
    )


def _host_lvs(lvs_results):
    """{host: LVs} of the loop of lvs over the hosts, each host once."""
    out = {}
    for r in _loop(lvs_results, "lvs"):
        host = r["item"]
        if not isinstance(host, str):
            raise AnsibleFilterError("lvs: an item is not a host name")
        what = "lvs on " + host
        if host in out:
            raise AnsibleFilterError("lvs: %s is listed twice" % host)
        result = _cmd(r, what)
        if result["rc"] != 0:
            raise AnsibleFilterError("%s: failed (rc %d)" % (what, result["rc"]))
        out[host] = _lvs(result["stdout"], what)
    return out


def cephx_lockbox_osds(osd_hosts, lvs_results, existing):
    """Each OSD (cephx_osd_hosts) with its lockbox entity, its number of LVs
    (from lvs on its host, the loop's registered result), whether it is
    encrypted (an LV of it has a ceph.cephx_lockbox_secret tag with a value)
    and the names (vg/lv, masked) of its LVs with more than one
    ceph.cephx_lockbox_secret tag, which the classification refuses. A down
    OSD's host is not read: it counts as encrypted when its lockbox entity
    is in existing (the entities of the cluster), and has no such LVs.
    {osd, host, osd_fsid, up, entity, lvs, encrypted, doubled}; no keys."""
    by_host = _host_lvs(lvs_results)
    out = []
    for o in osd_hosts:
        entity = "client.osd-lockbox." + o["osd_fsid"]
        lvs, encrypted, doubled = 0, False, []
        if not o["up"]:
            encrypted = entity in existing
        else:
            if o["host"] not in by_host:
                raise AnsibleFilterError("lvs: no result for %s" % o["host"])
            mine = _of_osd(by_host[o["host"]], o["osd"], o["osd_fsid"])
            lvs = len(mine)
            encrypted = any(s for _, _, _, secrets in mine for s in secrets)
            doubled = [_lv_shown(vg, lv) for vg, lv, _, s in mine if len(s) > 1]
        out.append(
            dict(o, entity=entity, lvs=lvs, encrypted=encrypted, doubled=doubled)
        )
    return out


# The copies


FAILED_STATES = {"skipped": "was skipped", "unreachable": "did not reach its host"}


def _want_fp(want):
    """The fingerprint of the key in force next of the lockbox keyring the
    play wants written (cephx_keyring, which fails the play if it cannot
    parse it)."""
    what = "the lockbox keyring"
    if not isinstance(want, Mapping) or _state(want) != "ok":
        raise AnsibleFilterError("%s: the inspection did not succeed" % what)
    fp = want.get("in_force_fp")
    if not isinstance(fp, str) or not fp:
        raise AnsibleFilterError("%s: in_force_fp is not a fingerprint" % what)
    return fp


def _differs(result, fp, what):
    """The copy that cephx_keyring inspected (result) does not carry the key
    of fingerprint fp. A result that failed or has no fingerprint is a copy
    that cannot be read: it differs."""
    if not isinstance(result, Mapping):
        raise AnsibleFilterError("%s: the result is not a mapping" % what)
    state = _state(result)
    if state in FAILED_STATES:
        raise AnsibleFilterError("%s %s" % (what, FAILED_STATES[state]))
    found = result.get("in_force_fp")
    if state == "failed" or not isinstance(found, str) or not found:
        return True
    return found != fp


def _exists(file_stat):
    what = "the stat of lockbox.keyring"
    if not isinstance(file_stat, Mapping) or "stat" not in file_stat:
        raise AnsibleFilterError("%s has no stat" % what)
    if _state(file_stat) != "ok":
        raise AnsibleFilterError("%s failed" % what)
    stat = file_stat["stat"]
    if not isinstance(stat, Mapping) or not isinstance(stat.get("exists"), bool):
        raise AnsibleFilterError("%s: exists is not a bool" % what)
    return stat["exists"]


def cephx_lockbox_copies(tag_keys, file_stat, file_key, want):
    """Which copies of one OSD's lockbox key to write: {tags: the names of
    the LVs whose tag does not carry the wanted key (tag_keys: cephx_keyring
    over the tags, a loop over cephx_osd_lvs's entries), file: whether
    lockbox.keyring exists and does not carry it (a bool)}. A missing
    lockbox.keyring is written by ceph-volume from the tag at the OSD's
    next start; file_key is read only when the file exists."""
    fp = _want_fp(want)
    what = "the inspection of the tags"
    tags = []
    for r in _loop(tag_keys, what):
        if _differs(r, fp, what + ": a result"):
            tags.append(r["item"]["name"])
    exists = _exists(file_stat)
    file = exists and _differs(file_key, fp, "the inspection of lockbox.keyring")
    return {"tags": tags, "file": file}


def _module_msg(result, what):
    """The module's message, trimmed and masked; '' without one."""
    msg = result.get("msg")
    if msg is None:
        return ""
    if not isinstance(msg, str):
        raise AnsibleFilterError("%s: msg is not a str" % what)
    return cephx_mask(msg.strip())


def cephx_lockbox_unwritten(tag_after, file_todo, file_after, want, path, host):
    """What does not carry the wanted key after the writes: one text per tag
    (tag_after: cephx_keyring over the tags read again, a loop over their
    names) and, if it was to be written (file_todo, a bool), for
    lockbox.keyring at path on host, with the module's message (masked)
    where it has one."""
    fp = _want_fp(want)
    if not isinstance(file_todo, bool):
        raise AnsibleFilterError("cephx_lockbox_unwritten: file_todo is not a bool")
    what = "the inspection of the written tags"
    out = [
        "the ceph.cephx_lockbox_secret tag of %s does not carry the new key"
        " after lvchange (lvm reading it from standard input)" % r["item"]
        for r in _loop(tag_after, what)
        if _differs(r, fp, what + ": a result")
    ]
    what = "the inspection of the written lockbox.keyring"
    if file_todo and _differs(file_after, fp, what):
        msg = _module_msg(file_after, what)
        out.append(
            "%s on %s does not carry the new key%s"
            % (path, host, " (%s)" % msg if msg else "")
        )
    return out


# The restart


def cephx_lockbox_get_refusal(get, entity):
    """The refusal after `ceph auth get <entity>` following the OSD's
    restart: the command failed (stderr masked) or did not print the
    entity's keyring. '' when it was skipped (no restart) or is fine."""
    if _state(get) == "skipped":
        return ""
    name = entity["name"]
    return _read(get, "ceph auth get " + name, _keyring_of(name))


def cephx_lockbox_done(entity, action, written, restarted, now):
    """What was done for one lockbox entity ({name, osd, host}): {name,
    class, action, osd, host, written, restarted, commit}. commit is who
    committed the key: '' (the keyring was not read again: no restart),
    play (still pending after the restart: the play commits it) or start."""
    what = "the keyring read after the restart"
    if not isinstance(now, Mapping):
        raise AnsibleFilterError("%s is not a mapping" % what)
    state = _state(now)
    if state == "skipped":
        commit = ""
    elif state != "ok":
        raise AnsibleFilterError("%s %s" % (what, FAILED_STATES.get(state, "failed")))
    elif not isinstance(now.get("has_pending"), bool):
        raise AnsibleFilterError("%s: has_pending is not a bool" % what)
    else:
        commit = "play" if now["has_pending"] else "start"
    return {
        "name": entity["name"],
        "class": "lockbox",
        "action": action,
        "osd": entity["osd"],
        "host": entity["host"],
        "written": written,
        "restarted": restarted,
        "commit": commit,
    }


# The OSD map around the restart of one OSD (_restart-osd.yml)


def _osd_entry(result, osd_id):
    """osd.<osd_id> in `ceph osd dump -f json` (result: its registered
    result): {up (bool), up_from (int)}, None if it is not listed. Every
    entry is checked: osd an int, up exactly 0 or 1, up_from an int, no
    OSD twice."""
    what = "ceph osd dump"
    n = _osd_id(osd_id, what)
    up = _osds_up(result)
    up_from = {e["osd"]: e["up_from"] for e in _osd_map(result, {"up_from": int})}
    if n not in up:
        return None
    return {"up": up[n], "up_from": up_from[n]}


def cephx_osd_state(result, osd_id):
    """osd.<osd_id> in `ceph osd dump -f json` before its restart: {up,
    up_from}, {} if it is not listed. The play checks rc first."""
    return _osd_entry(result, osd_id) or {}


def _parses(text):
    try:
        json.loads(text)
    except ValueError:
        return False
    return True


def cephx_osd_back(result, osd_id, up_from):
    """Whether one answer of `ceph osd dump -f json` after the restart of
    osd.<osd_id> shows it up with an up_from newer than up_from (its
    up_from before). A command that failed, an answer that is not JSON and
    an OSD missing from the map are "not yet"; an answer of another shape
    stops."""
    if not _is(up_from, int):
        raise AnsibleFilterError("cephx_osd_back: up_from is not an int")
    r = _cmd(result, "ceph osd dump")
    if r["rc"] != 0 or not _parses(r["stdout"]):
        return False
    e = _osd_entry(r, osd_id)
    return e is not None and e["up"] and e["up_from"] > up_from


def cephx_osd_back_until(result, osd_id, up_from):
    """The wait's `until`: cephx_osd_back, except that an answer it cannot
    judge ends the wait (True): the wait task is no_log, so its stop would
    be censored; cephx_osd_back stops on it after the loop, readably."""
    try:
        return cephx_osd_back(result, osd_id, up_from)
    except AnsibleFilterError:
        return True


class FilterModule:
    def filters(self):
        return {
            f.__name__: _guarded(f.__name__)(f)
            for f in (
                cephx_osd_lvs,
                cephx_lockbox_doubled,
                cephx_lockbox_two_tags,
                cephx_lockbox_osds,
                cephx_lockbox_copies,
                cephx_lockbox_unwritten,
                cephx_lockbox_get_refusal,
                cephx_lockbox_done,
                cephx_osd_state,
                cephx_osd_back,
                cephx_osd_back_until,
            )
        }
