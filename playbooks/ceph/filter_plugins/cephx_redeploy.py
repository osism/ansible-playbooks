"""The redeploys of cephadm-rotate-keys (_redeploy-daemons.yml,
_redeploy-daemons-batch.yml), and what was done for a group of rotated
keys.

cephx_redeploy_read_refusal judges the reads before the redeploys (the
fsid, the monitors' keyrings, cephadm's list of daemons). The others
decide: which daemons cephadm has not yet listed as refreshed
(cephx_redeploy_pending for one answer, cephx_redeploy_stale for the
wait's results), which to redeploy and why (cephx_redeploy_plan,
cephx_redeploy_result), whether cephadm refused a redeploy
(cephx_redeploy_refusal) and which daemons came back in a new container
(cephx_redeploy_up, cephx_redeploy_up_daemons).
cephx_rotate_group_done notes what was done for one group of rotated keys
(_rotate-keys-rotate.yml).

The input is checked as cephx_common says. A requested daemon listed
twice in `ceph orch ps`, or a requested daemon type without its result,
stops. In the waits a
command that failed, an answer that is not JSON and a daemon missing from
the answer count as "not yet": a daemon being redeployed can vanish from
cephadm's list for a moment. The waits' tasks are no_log, so the filters
of their `until` (cephx_redeploy_pending, cephx_redeploy_up) end the wait
on an answer they cannot judge, and the filters after the loop
(cephx_redeploy_stale, cephx_redeploy_up_daemons) stop on it, readably.

The registered results read here carry no keys that leave a filter: `ceph
auth get` is judged by its first line and return code only, the keyrings
by their fingerprints.
"""

import datetime
import importlib.util
import json
import os
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
_fsid = _common._fsid
_is = _common._is
_keyring_of = _common._keyring_of
_loop = _common._loop
_loop_failures = _common._loop_failures
_read = _common._read
_records = _common._records
_state = _common._state

# The times in `ceph orch ps` (last_refresh, started), UTC.
TIME = "%Y-%m-%dT%H:%M:%S.%fZ"
EPOCH = datetime.datetime(1970, 1, 1)


def _type_of(daemon):
    """The daemon type of a daemon name (crash.node-0: crash)."""
    return daemon.partition(".")[0]


def _types(daemons):
    """The daemon types of the daemons, in their order."""
    return list(dict.fromkeys(_type_of(d["daemon"]) for d in daemons))


def _ps_what(daemon_type):
    return "ceph orch ps --daemon-type %s" % daemon_type


# The reads before the redeploys


def _sentences(refusals):
    return " ".join(e for e in refusals if e)


def _read_auth_get(result):
    """Each `ceph auth get` (the loop's registered result) that failed or did
    not print the keyring of its entity (its first line [<entity>])."""
    return _sentences(
        _read(r, "ceph auth get %s" % r["item"], _keyring_of(r["item"]))
        for r in _loop(result, "ceph auth get")
    )


def _read_orch_ps(result):
    """Each `ceph orch ps --daemon-type <type>` (the loop's registered
    result) that failed or did not print JSON. JSON of another shape (not
    a list of entries with a daemon_name) stops."""

    def read(r):
        what = _ps_what(r["item"])

        def check(stdout):
            if not _parses(stdout):
                return "did not print JSON"
            _rows(stdout, what, ())
            return ""

        return _read(r, what, check)

    return _sentences(read(r) for r in _loop(result, "ceph orch ps"))


READS = {
    "fsid": lambda r: _read(r, "ceph fsid", _fsid),
    "auth_get": _read_auth_get,
    "orch_ps": _read_orch_ps,
}


def cephx_redeploy_read_refusal(name, result):
    """The refusal after the read `name` (a key of READS) of
    _redeploy-daemons.yml: the command failed (stderr masked) or printed
    something else than expected; '' when it is fine."""
    if name not in READS:
        raise AnsibleFilterError("cephx_redeploy_read_refusal: no read %s" % name)
    return READS[name](result)


# The listings of `ceph orch ps`


def _by_type(registered, types, what):
    """The results of a loop over daemon types, by type: one for each of
    types."""
    by = {}
    for r in _loop(registered, what):
        if r["item"] in by:
            raise AnsibleFilterError("%s: two results" % _ps_what(r["item"]))
        by[r["item"]] = r
    for t in types:
        if t not in by:
            raise AnsibleFilterError("%s: no result" % _ps_what(t))
    return by


def _rows(stdout, what, names):
    """The entries of these daemons in a listing (a JSON list of objects,
    each with a daemon_name), by name; one of them listed twice stops."""
    rows = {}
    for e in _records(stdout, what, list, {"daemon_name": str}):
        n = e["daemon_name"]
        if n in names:
            if n in rows:
                raise AnsibleFilterError("%s: %s is listed twice" % (what, n))
            rows[n] = e
    return rows


def _parses(text):
    try:
        json.loads(text)
    except ValueError:
        return False
    return True


def _poll(result, what, names):
    """The entries of these daemons in one answer of a wait, by name; None
    (not yet) if the command failed or did not print JSON."""
    r = _cmd(result, what)
    if r["rc"] != 0 or not _parses(r["stdout"]):
        return None
    return _rows(r["stdout"], what, names)


def _time(value, field, what):
    try:
        return datetime.datetime.strptime(value, TIME)
    except (TypeError, ValueError):
        pass
    # Refused outside the except block: strptime's message quotes the value.
    raise AnsibleFilterError("%s: a %s is not a time" % (what, field))


def _optional(entry, field, what):
    """A field that cephadm leaves out when it has no value: a str, or None
    when it is missing or null."""
    value = entry.get(field)
    if not isinstance(value, (str, type(None))):
        raise AnsibleFilterError("%s: a %s is not a str" % (what, field))
    return value


# The wait for cephadm's refreshed list of daemons


def _names_of_type(daemons, daemon_type):
    return [d["daemon"] for d in daemons if _type_of(d["daemon"]) == daemon_type]


def _refreshed(entry, what):
    """When cephadm last refreshed an entry, None if never."""
    if "last_refresh" not in entry:
        return None
    return _time(entry["last_refresh"], "last_refresh", what)


def _seen(kick, daemon_type, names):
    """The newest refresh of these daemons in the answer to the kick (None if
    none): the answer that counts is refreshed after it."""
    what = _ps_what(daemon_type)
    kicked = _by_type(kick, [daemon_type], "ceph orch ps")[daemon_type]
    rows = _rows(_cmd(kicked, what)["stdout"], what, names)
    times = [t for t in (_refreshed(e, what) for e in rows.values()) if t]
    return max(times, default=None)


def _pending(result, daemon_type, daemons, kick):
    """The daemons of daemon_type that one answer of `ceph orch ps
    --daemon-type <type> --refresh` (result) does not list as refreshed
    after the kick (kick: the loop's registered result): missing from the
    answer, never refreshed, or refreshed no later than the newest refresh
    the kick's answer showed. All of them if the command failed or did not
    print JSON. An answer that cannot be judged (JSON of another shape, a
    daemon listed twice, a time that is not one) stops."""
    what = _ps_what(daemon_type)
    names = _names_of_type(daemons, daemon_type)
    if not names:
        raise AnsibleFilterError("%s: no daemons of the type" % what)
    seen = _seen(kick, daemon_type, names)
    rows = _poll(result, what, names)
    if rows is None:
        return names
    out = []
    for n in names:
        t = _refreshed(rows[n], what) if n in rows else None
        if t is None or (seen is not None and t <= seen):
            out.append(n)
    return out


def cephx_redeploy_pending(result, daemon_type, daemons, kick):
    """The wait's `until`: the daemons still to wait for after one answer
    (see _pending). An answer that cannot be judged ends the wait ([]):
    the wait task is no_log, so its stop would be censored;
    cephx_redeploy_stale stops on it after the loop, readably."""
    try:
        return _pending(result, daemon_type, daemons, kick)
    except AnsibleFilterError:
        return []


def cephx_redeploy_stale(ps, daemons, kick):
    """The daemons not listed as refreshed when the wait ended (ps: its
    registered result, one per daemon type), each type's last answer
    judged as _pending does; an answer that cannot be judged stops."""
    types = _types(daemons)
    by_type = _by_type(ps, types, "ceph orch ps")
    out = []
    for t in types:
        out += _pending(by_type[t], t, daemons, kick)
    return out


# The redeploys

NO_FILE = "no keyring file on its host"
UNREADABLE = "its keyring on the host cannot be read"
DIFFERS = "its keyring on the host differs from the monitors' key"
STARTED_BEFORE = "its container started before the keyring was written"


def _by_item(registered, key, what):
    """The results of a loop, by key(item)."""
    return {key(r["item"]): r for r in _loop(registered, what)}


def _result_of(by, key, name, what):
    if key not in by:
        raise AnsibleFilterError("%s: no result of %s" % (name, what))
    return by[key]


def _keyring_file(result, name):
    """The stat of a daemon's keyring file: exists, and mtime when it
    exists."""
    stat = result.get("stat") if _state(result) == "ok" else None
    if not isinstance(stat, Mapping) or not _is(stat.get("exists"), bool):
        raise AnsibleFilterError("%s: the stat of its keyring has no exists" % name)
    if stat["exists"] and not _is(stat.get("mtime"), (int, float)):
        raise AnsibleFilterError("%s: the stat of its keyring has no mtime" % name)
    return stat


def _file_fp(result, name):
    """The fingerprint of the key in force in a daemon's keyring file; None
    if the inspection gave none (failed_when: false: the file cannot be
    read or parsed)."""
    state = _state(result)
    if state in ("skipped", "unreachable"):
        raise AnsibleFilterError("%s: its keyring was not inspected" % name)
    if state == "failed":
        return None
    fp = result.get("in_force_fp")
    return fp if isinstance(fp, str) and fp else None


def _mon_fp(result, entity):
    """The fingerprint of the monitors' key of an entity."""
    fp = result.get("in_force_fp") if _state(result) == "ok" else None
    if not (isinstance(fp, str) and fp):
        raise AnsibleFilterError("%s: the monitors' key has no fingerprint" % entity)
    return fp


def _started(entry, what):
    """The start time of a container in seconds since the epoch; 0 when
    cephadm shows none, so that the daemon counts as started before its
    keyring was written and is redeployed (the safe side)."""
    started = entry.get("started")
    if started is None or started == "":
        return 0
    return (_time(started, "start time", what) - EPOCH).total_seconds()


def _listed(entry, what):
    """What the plan needs of a daemon's entry in `ceph orch ps`."""
    return {
        "status_desc": _optional(entry, "status_desc", what),
        "container_id": _optional(entry, "container_id", what) or "",
        "started": _started(entry, what),
    }


def _why(stat, file_fp, mon_fp, listed):
    """Why a daemon is redeployed, '' to keep it; the first reason that
    applies."""
    if not stat["exists"]:
        return NO_FILE
    if file_fp is None:
        return UNREADABLE
    if file_fp != mon_fp:
        return DIFFERS
    if listed is None:
        return "not running (not listed)"
    if listed["status_desc"] != "running":
        return "not running (%s)" % (listed["status_desc"] or "no status")
    if listed["started"] <= stat["mtime"]:
        return STARTED_BEFORE
    return ""


def cephx_redeploy_plan(daemons, ps, files, file_keys, mon_keys):
    """For each daemon ({daemon, entity, host}), why it is redeployed, '' to
    keep it: {daemon, entity, host, container_id, why}. Kept only if its
    keyring file on its host (files: stat results) carries the monitors' key
    (file_keys, mon_keys: cephx_keyring results, fingerprints), `ceph orch
    ps` (ps: the wait's results, one per daemon type) shows it running, and
    its container started after the file was written. A keyring inspection
    without a fingerprint (failed, failed_when: false) means the file
    cannot be read."""
    types = _types(daemons)
    by_type = _by_type(ps, types, "ceph orch ps")
    listed = {}
    for t in types:
        what = _ps_what(t)
        rows = _poll(by_type[t], what, _names_of_type(daemons, t))
        if rows is None:
            raise AnsibleFilterError("%s: failed or did not print JSON" % what)
        listed.update((n, _listed(e, what)) for n, e in rows.items())
    stats = _by_item(files, lambda i: i["daemon"], "the stat of the keyrings")
    file_keys = _by_item(file_keys, lambda i: i["daemon"], "the keyring files")
    mon_keys = _by_item(mon_keys, lambda i: i, "the monitors' keyrings")
    out = []
    for d in daemons:
        name, entity = d["daemon"], d["entity"]
        mon_fp = _mon_fp(
            _result_of(mon_keys, entity, entity, "the monitors' keyrings"), entity
        )
        stat = _keyring_file(
            _result_of(stats, name, name, "the stat of the keyrings"), name
        )
        file_fp = None
        if stat["exists"]:
            file_fp = _file_fp(
                _result_of(file_keys, name, name, "the keyring files"), name
            )
        mine = listed.get(name)
        out.append(
            {
                "daemon": name,
                "entity": entity,
                "host": d["host"],
                "container_id": mine["container_id"] if mine else "",
                "why": _why(stat, file_fp, mon_fp, mine),
            }
        )
    return out


def cephx_redeploy_result(plan):
    """{daemon, entity, action} of each daemon of the plan, action redeployed
    (it had a reason) or kept."""
    return [
        {
            "daemon": p["daemon"],
            "entity": p["entity"],
            "action": "redeployed" if p["why"] else "kept",
        }
        for p in plan
    ]


def cephx_redeploy_refusal(cmd):
    """The redeploys cephadm refused (the loop's registered result), its
    stderr masked, or ''."""
    return _loop_failures(cmd, "ceph orch daemon redeploy", lambda i: i["daemon"])


def _up(result, item):
    """Whether one answer of `ceph orch ps --daemon-type <type> --refresh`
    shows the daemon of item ({daemon, container_id}: the container before
    its redeploy, '' if none) running in another container. Not yet if the
    command failed, did not print JSON or does not list the daemon; an
    answer that cannot be judged (JSON of another shape, the daemon listed
    twice) stops."""
    daemon = item["daemon"]
    what = _ps_what(_type_of(daemon))
    rows = _poll(result, what, [daemon])
    if rows is None or daemon not in rows:
        return False
    status = _optional(rows[daemon], "status_desc", what)
    container_id = _optional(rows[daemon], "container_id", what) or ""
    return status == "running" and container_id not in ("", item["container_id"])


def cephx_redeploy_up(result, item):
    """The wait's `until`: whether the wait for the daemon of item can end,
    because one answer shows it in a new container (see _up) or cannot be
    judged. The wait task is no_log, so a stop there would be censored;
    cephx_redeploy_up_daemons stops on such an answer after the loop,
    readably."""
    try:
        return _up(result, item)
    except AnsibleFilterError:
        return True


def cephx_redeploy_up_daemons(wait):
    """The daemons that run in another container when the wait ended (wait:
    its registered result, one per daemon of the batch), each one's last
    answer judged as _up does; an answer that cannot be judged stops."""
    return [
        r["item"]["daemon"] for r in _loop(wait, "ceph orch ps") if _up(r, r["item"])
    ]


def cephx_rotate_group_done(group, redeploy_result, set_entity_key_results):
    """What was done for each entity of a group of rotated keys ({names,
    class, daemons}): {name, class, action, checkout ([]), monitors (false),
    redeployed, kept}. action is the last of _set-entity-key.yml for the
    entity, its final state; redeployed and kept are its daemons
    (redeploy_result, as cephx_redeploy_result gives it)."""
    out = []
    for n in group["names"]:
        mine = [m for m in redeploy_result if m["entity"] == n]
        actions = [a for a in set_entity_key_results if a["name"] == n]
        if not actions:
            raise AnsibleFilterError("%s: no action of the rotation" % n)
        done = {
            "name": n,
            "class": group["class"],
            "action": actions[-1]["action"],
            "checkout": [],
            "monitors": False,
            "redeployed": [],
            "kept": [],
        }
        if group["daemons"]:
            for m in mine:
                done[m["action"]].append(m["daemon"])
        out.append(done)
    return out


class FilterModule:
    def filters(self):
        return {
            f.__name__: _guarded(f.__name__)(f)
            for f in (
                cephx_redeploy_read_refusal,
                cephx_redeploy_pending,
                cephx_redeploy_stale,
                cephx_redeploy_plan,
                cephx_redeploy_result,
                cephx_redeploy_refusal,
                cephx_redeploy_up,
                cephx_redeploy_up_daemons,
                cephx_rotate_group_done,
            )
        }
