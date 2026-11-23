"""The checks of validate-ceph-keys.

One filter per check returns the check's report rows, each
{entity, location, result, note}; cephx_validator_tests collects them into
the report's tests and cephx_validator_lines gives the lines printed.

The inputs are the registered results of the validator's tasks, checked
as cephx_common says. None of them is a key: the keyrings and libvirt
secrets are read and fingerprinted by no_log tasks, and the checks see
only the fingerprints (the fingerprint results also carry the secrets'
values in their items, which are never read here). The one exception, the
results of `ceph auth get`, whose stdout is the keyring:
cephx_auth_get_failed reads only their rc and stderr.
"""

import calendar
import importlib.util
import os
import re
import sys
import time
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
_failure = _common._failure
_is = _common._is
_loop = _common._loop
_loop_failures = _common._loop_failures
_openstack_key_names = _common._openstack_key_names
_osd_map = _common._osd_map
_read = _common._read
_records = _common._records
_state = _common._state
cephx_mask = _common.cephx_mask

LOCKBOX_PREFIX = "client.osd-lockbox."
REPO_STEP = (
    "staged, not committed yet: copy the keyring files of the checkout into the"
    " repository, commit, push, osism apply configuration, then "
)
FIRST_USE = "; the first use of the new key commits it"
UNREACHABLE = "the host cannot be reached"
OTHER_KEY = "holds another key than the key in force next"
PENDING_LINE = "carries a pending key line, which Ceph clients cannot read"
UTC_FORMAT = "%Y-%m-%d %H:%M:%S UTC"
GUEST_NAME = re.compile(r"-name guest=([^, ]+)")
GUEST_UUID = re.compile(
    r"-uuid ([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)
# A line of `stat -c '%Y %n'` of the container's copies of the secrets.
CONTAINER_TIME = re.compile(r"([0-9]+) /etc/libvirt/secrets/(.+)")
NO_TIMES = "stat did not print a time for each"


def _row(entity, location, result, note):
    return {"entity": entity, "location": location, "result": result, "note": note}


def _joined(head, detail):
    """head, followed by ': detail' when there is a detail."""
    return head + ": " + detail if detail else head


def _msg(result):
    """A module's message, trimmed and masked; '' without one."""
    msg = result.get("msg")
    return cephx_mask(msg.strip()) if isinstance(msg, str) else ""


# Check 1: pending keys


def _osds(osd_dump):
    """{fsid: osd id} of `ceph osd dump`; {} if the read was skipped (no
    pending lockbox key). Two OSDs with one fsid stop."""
    what = "ceph osd dump"
    if _state(osd_dump) == "skipped":
        return {}
    failed = _read(osd_dump, what, lambda stdout: "")
    if failed:
        raise AnsibleFilterError(failed)
    out = {}
    for e in _osd_map(osd_dump, {"osd": int, "uuid": str}):
        if e["uuid"] in out:
            raise AnsibleFilterError(
                "%s: osd.%d and osd.%d have the same uuid"
                % (what, out[e["uuid"]], e["osd"])
            )
        out[e["uuid"]] = e["osd"]
    return out


def _pending_note(name, osds, services, openstack_names):
    if name in services:
        return (
            REPO_STEP
            + "osism apply "
            + ", then osism apply ".join(services[name])
            + (
                "; then live-migrate every running guest"
                if name in ("client.cinder", "client.nova")
                else ""
            )
            + FIRST_USE
        )
    if name in openstack_names:
        return REPO_STEP + "apply the services that use " + name + FIRST_USE
    if name.startswith(LOCKBOX_PREFIX):
        fsid = name[len(LOCKBOX_PREFIX) :]
        if fsid not in osds:
            return "staged lockbox key, but no OSD in the OSD map has the fsid it is named after"
        return "staged lockbox key of osd.%d: its next start commits it" % osds[fsid]
    return (
        "a pending key: find out what uses this entity, then ceph auth commit-pending "
        + name
        + " or ceph auth clear-pending "
        + name
    )


def cephx_check_pending(cluster, osd_dump, services, openstack_keys):
    """Rows of check 1, one per entity with a pending key, with what commits it.

    cluster: cephx_auth_export's result; osd_dump: the registered `ceph osd
    dump -f json` (skipped without pending lockbox keys); services: the
    _cephx_key_services map; openstack_keys: the site's openstack_keys.
    """
    osds = _osds(osd_dump)
    openstack_names = _openstack_key_names(openstack_keys)
    return [
        _row(
            name,
            "cluster",
            "pending",
            _pending_note(name, osds, services, openstack_names),
        )
        for name, flags in cluster.items()
        if flags["pending"]
    ]


# Check 2: old key type


def cephx_aes_allowed(stdout):
    """Whether the monitors' auth_allowed_ciphers (`ceph mon dump -f json`)
    allows aes (value 1); a monitor map without it allows aes."""
    what = "ceph mon dump"
    monmap = _records(stdout, what, dict, {})
    if "auth_allowed_ciphers" not in monmap:
        return True
    ciphers = monmap["auth_allowed_ciphers"]
    if not isinstance(ciphers, list) or not all(
        isinstance(c, dict) and _is(c.get("value"), int) for c in ciphers
    ):
        raise AnsibleFilterError("%s: unexpected auth_allowed_ciphers" % what)
    return any(c["value"] == 1 for c in ciphers)


def cephx_check_old(cluster):
    """Rows of check 2, one per entity whose key in force next is aes."""
    return [
        _row(name, "cluster", "aes", "its key in force is of the old type aes")
        for name, flags in cluster.items()
        if flags["aes"]
    ]


# Checks 3 and 4: keyring files, read by cephx_keyring


def _read_state(read, what):
    """'unreachable', 'unreadable' or 'read' of a cephx_keyring result
    (failed_when: false: a file that cannot be read or parsed has no
    entity, and the module's message says why)."""
    state = _state(read)
    if state == "skipped":
        raise AnsibleFilterError("%s: a read was skipped" % what)
    if state == "unreachable":
        return "unreachable"
    if state == "failed" or "entity" not in read:
        return "unreadable"
    return "read"


def _keyring_verdict(read, name, fps):
    """(result, note) of a keyring read by cephx_keyring, None if it holds
    the key in force next."""
    what = "cephx_keyring"
    if not isinstance(read["entity"], str):
        raise AnsibleFilterError("%s: entity is not a str" % what)
    if read["entity"] != name:
        return "differs", "the keyring of " + read["entity"]
    if not isinstance(read.get("has_pending"), bool):
        raise AnsibleFilterError("%s: has_pending is not a bool" % what)
    if read["has_pending"]:
        return "differs", PENDING_LINE
    fp, want = read.get("key_fp"), fps.get(name)
    if not (isinstance(fp, str) and fp and isinstance(want, str) and want):
        # Nothing to compare: stop, never "matches". An entity name is not
        # a key.
        raise AnsibleFilterError("no fingerprint to compare for " + name)
    if fp != want:
        return "differs", OTHER_KEY
    return None


def _monitor_stat(s, what):
    """Whether the file exists, from an ok stat result."""
    st = s.get("stat")
    if not isinstance(st, Mapping):
        raise AnsibleFilterError("%s: the result has no stat" % what)
    if not isinstance(st.get("exists"), bool):
        raise AnsibleFilterError("%s: stat.exists is not a bool" % what)
    return st["exists"]


def cephx_check_monitor(stat, read, fps):
    """Rows of check 3, one per monitor host and entity.

    stat: the registered stat of /etc/ceph/ceph.<entity>.keyring per
    [host, entity]; read: the registered cephx_keyring reads of the files
    that exist; fps: the fingerprints of the keys in force next. A host
    that cannot be reached is a failed row.
    """
    stat_what = "stat of the monitor keyrings"
    read_what = "cephx_keyring of the monitor keyrings"
    stats = _loop(stat, stat_what)
    reads = _loop(read, read_what)
    out = []
    for s in stats:
        host, name = s["item"]
        m = next((r for r in reads if r["item"] == s["item"]), None)
        state = _state(s)
        read_state = _read_state(m, read_what) if m is not None else "unreadable"
        if state == "unreachable" or read_state == "unreachable":
            r, note = "failed", UNREACHABLE
        elif state == "skipped":
            raise AnsibleFilterError("%s: a stat was skipped" % stat_what)
        elif state == "failed":
            r, note = "failed", _joined("the stat failed", _msg(s))
        elif not _monitor_stat(s, stat_what):
            r, note = (
                "missing",
                "no such file: copy-ceph-keys reads the keyring from here and would skip it",
            )
        elif read_state == "unreadable":
            r, note = "unreadable", (_msg(m) if m is not None else "") or "not read"
        else:
            r, note = _keyring_verdict(m, name, fps) or (
                "matches",
                "/etc/ceph/ceph." + name + ".keyring",
            )
        out.append(_row(name, host, r, note))
    return out


def _git_verdict(g):
    failed = _failure(g)
    if failed:
        return "uncommitted", "git status " + failed
    st = g["stdout"][:2]
    if st == "??":
        return (
            "uncommitted",
            "matches, but is not in the repository (git status: untracked)",
        )
    if st == "!!":
        return (
            "uncommitted",
            "matches, but is not in the repository (git status: ignored)",
        )
    if st.strip():
        return (
            "uncommitted",
            "matches, but differs from the commit (git status: "
            + st.strip()
            + "): commit and push it, then osism apply configuration",
        )
    return "matches", ""


def cephx_check_checkout(files, read, git, cluster, fps, checkout_dir):
    """Rows of check 4, one per keyring file of the checkout.

    files: the files ({name, dest}); read and git: the registered
    cephx_keyring reads and `git status` of these files (loops over them);
    cluster: cephx_auth_export's result; fps: the fingerprints of the keys
    in force next; checkout_dir: configuration_directory, None when it is
    unset or null: then one failed row, and the play has read nothing.
    """
    if checkout_dir is None:
        return [
            _row("checkout", "manager", "failed", "configuration_directory is not set")
        ]
    read_what = "cephx_keyring of the checkout's keyring files"
    reads = _loop(read, read_what)
    gits = [_cmd(g, "git status") for g in _loop(git, "git status")]
    if [r["item"] for r in reads] != files or [g["item"] for g in gits] != files:
        raise AnsibleFilterError(
            "the reads of the checkout's keyring files are not those of its files"
        )
    out = []
    for f, m, g in zip(files, reads, gits):
        read_state = _read_state(m, read_what)
        if f["name"] not in cluster:
            r, note = "no-entity", "no such entity on the cluster (ceph auth export)"
        elif read_state == "unreachable":
            r, note = "failed", UNREACHABLE
        elif read_state == "unreadable":
            r, note = "unreadable", _joined(
                "cannot be read, decrypted or parsed on the Ansible controller",
                _msg(m),
            )
        else:
            r, note = _keyring_verdict(m, f["name"], fps) or _git_verdict(g)
        out.append(_row(f["name"], f["dest"], r, note))
    return out


# Check 5: running guests


def _found_files(r, host):
    """The files of an ok find result, each with a path and an mtime."""
    what = "find on " + host
    if "files" not in r:
        raise AnsibleFilterError("%s: the result has no files" % what)
    if not isinstance(r["files"], list):
        raise AnsibleFilterError("%s: files is not a list" % what)
    for f in r["files"]:
        if not isinstance(f, dict):
            raise AnsibleFilterError("%s: a file is not an object" % what)
        for field in ("path", "mtime"):
            if field not in f:
                raise AnsibleFilterError("%s: a file has no %s" % (what, field))
        if not isinstance(f["path"], str):
            raise AnsibleFilterError("%s: a file's path is not a str" % what)
        if not _is(f["mtime"], (int, float)):
            raise AnsibleFilterError("%s: a file's mtime is not a number" % what)
    return r["files"]


def cephx_compute_secrets(found, secret_uuids):
    """Per compute node {host, reachable, files, mtime}: the libvirt secrets
    in kolla's directory (only those of secret_uuids, if any) and the latest
    of their modification times (0 without secrets).

    found: the registered find of *.base64 per compute node (a node that
    cannot be reached is not reachable).
    """
    pattern = None
    if secret_uuids:
        pattern = re.compile(
            "/(" + "|".join(re.escape(u) for u in secret_uuids) + ")[.]base64$"
        )
    out = []
    for r in _loop(found, "find of the libvirt secrets"):
        host = r["item"]
        state = _state(r)
        if state == "skipped":
            raise AnsibleFilterError("find on %s: the find was skipped" % host)
        if state == "failed":
            raise AnsibleFilterError("find on %s failed" % host)
        reachable = state != "unreachable"
        files = _found_files(r, host) if reachable else []
        if pattern:
            files = [f for f in files if pattern.search(f["path"])]
        out.append(
            {
                "host": host,
                "reachable": reachable,
                "files": [os.path.basename(f["path"]) for f in files],
                "mtime": max(int(f["mtime"]) for f in files) if files else 0,
            }
        )
    return out


def _secret_names(f, rbd_secret_uuid, cinder_rbd_secret_uuid):
    """The entities whose key a secret file may hold: by its UUID, when
    rbd_secret_uuid or cinder_rbd_secret_uuid name it, else either."""
    u = re.sub("[.]base64$", "", f)
    if rbd_secret_uuid and u == rbd_secret_uuid:
        return ["client.nova"]
    if cinder_rbd_secret_uuid and u == cinder_rbd_secret_uuid:
        return ["client.cinder"]
    return ["client.nova", "client.cinder"]


def _secret_problems(
    c, fp_results, fps, container, rbd_secret_uuid, cinder_rbd_secret_uuid
):
    """What is wrong with the secrets of compute node c: each file's copies
    (kolla's, the container's) must hold the key in force of its entity."""
    bad = []
    for f in c["files"]:
        names = _secret_names(f, rbd_secret_uuid, cinder_rbd_secret_uuid)
        names = [n for n in names if n in fps]
        expect = [fps[n] for n in names]
        if not expect:
            continue
        for copy in ("kolla", "container"):
            r = fp_results.get((c["host"], f, copy))
            where = (
                "kolla's copy"
                if copy == "kolla"
                else "the " + container + " container's copy"
            )
            if r is None or _state(r) in ("skipped", "unreachable"):
                bad.append(f + ": " + where + " cannot be read")
            elif "key_fp" not in r:
                bad.append(f + ": " + where + " does not hold a cephx key")
            elif r["key_fp"] not in expect:
                bad.append(
                    f
                    + ": "
                    + where
                    + " holds another key than the one in force for "
                    + " or ".join(names)
                )
    return bad


def _fingerprints(secret_fps):
    """{(host, file, copy): result} of the fingerprints of the secrets."""
    what = "cephx_keyring of the libvirt secrets"
    out = {}
    for r in _loop(secret_fps, what):
        if "key_fp" in r and not isinstance(r["key_fp"], str):
            raise AnsibleFilterError("%s: key_fp is not a str" % what)
        i = r["item"]
        out[(i["host"], i["file"], i["copy"])] = r
    return out


def _container_times(d, files, host, container):
    """({file: time}, None) of the container's copies of the secrets
    (`stat -c '%Y %n'`), or (None, why not): every file needs exactly one
    valid time."""
    if d is None:
        return None, "no result"
    r = _cmd(d, "stat in the %s container on %s" % (container, host))
    if r["rc"] != 0:
        return None, "rc %d" % r["rc"]
    times = {}
    for line in r["stdout"].splitlines():
        m = CONTAINER_TIME.fullmatch(line)
        if not m or m.group(2) not in files or m.group(2) in times:
            return None, NO_TIMES
        times[m.group(2)] = int(m.group(1))
    if len(times) != len(files):
        return None, NO_TIMES
    return times, None


def _started(line):
    """The start time (ps lstart, UTC) at the start of a ps line, in
    seconds since the epoch."""
    try:
        return calendar.timegm(time.strptime(line[:24], "%a %b %d %H:%M:%S %Y"))
    except ValueError:
        raise AnsibleFilterError(
            "ps printed a start time that cannot be read"
        ) from None


def _guest_rows(host, lines, cutoff):
    out = []
    for line in lines:
        if "qemu" not in line or "-name guest=" not in line:
            continue
        name = GUEST_NAME.search(line)
        uuid = GUEST_UUID.search(line)
        started = _started(line)
        old = started <= cutoff
        out.append(
            _row(
                (name.group(1) if name else "")
                + (" (" + uuid.group(1) + ")" if uuid else ""),
                host,
                "failed" if old else "passed",
                "started "
                + time.strftime(UTC_FORMAT, time.gmtime(started))
                + (
                    ", before libvirt loaded the current secrets: it holds the old key; live-migrate it (or stop and start it)"
                    if old
                    else ""
                ),
            )
        )
    return out


def _processes(p, host, cutoff):
    """The rows of the guests of a host from its ps result."""
    if p is None:
        return [_row("processes", host, "failed", "ps failed (no result)")]
    if _state(p) == "unreachable":
        return [_row("host", host, "failed", UNREACHABLE)]
    r = _cmd(p, "ps on " + host)
    failed = _failure(r)
    if failed:
        return [_row("processes", host, "failed", "ps " + failed)]
    return _guest_rows(host, r["stdout"].splitlines(), cutoff)


def cephx_check_guests(
    compute,
    secret_fps,
    container_secrets,
    ps,
    fps,
    secrets_dir,
    container,
    rbd_secret_uuid="",
    cinder_rbd_secret_uuid="",
    secret_uuids=(),
):
    """Rows of check 5, per compute node: its secrets, then its guests.

    compute: cephx_compute_secrets' result; secret_fps: the registered
    cephx_keyring fingerprints of the secrets (items {host, file, copy});
    container_secrets: the registered `stat -c '%Y %n'` of the container's
    copies per node; ps: the registered `ps -eww -o lstart=,args=` per node
    (in UTC); fps: the fingerprints of the keys in force; secret_uuids:
    the configured UUIDs (_keys_secret_uuids), named when a node has none
    of their secrets. The guests of a node are compared only when both
    copies of its secrets hold the keys in force and the container's copy
    of each has a time.
    """
    fp_results = _fingerprints(secret_fps)
    times_of = {
        r["item"]["host"]: r
        for r in _loop(container_secrets, "stat in the %s container" % container)
    }
    ps_of = {r["item"]["host"]: r for r in _loop(ps, "ps")}
    out = []
    for c in compute:
        host = c["host"]
        if not c["reachable"]:
            out.append(_row("host", host, "failed", UNREACHABLE))
            continue
        if not c["files"]:
            out.append(
                _row(
                    "secrets",
                    host,
                    "skipped",
                    "no libvirt secrets in "
                    + secrets_dir
                    + ((" for " + ", ".join(secret_uuids)) if secret_uuids else "")
                    + ": no Nova with Ceph on this host",
                )
            )
            continue
        bad = _secret_problems(
            c, fp_results, fps, container, rbd_secret_uuid, cinder_rbd_secret_uuid
        )
        if bad:
            out.append(
                _row(
                    "secrets",
                    host,
                    "failed",
                    "; ".join(bad)
                    + ". osism apply nova has not given this host the current keys (or its "
                    + container
                    + " container has not been restarted since); its guests are not compared",
                )
            )
            continue
        d = times_of.get(host)
        if d is not None and _state(d) == "unreachable":
            out.append(_row("host", host, "failed", UNREACHABLE))
            continue
        files = ", ".join(c["files"])
        times, why = _container_times(d, c["files"], host, container)
        if times is None:
            out.append(
                _row(
                    "secrets",
                    host,
                    "failed",
                    "the %s container's copies of the secrets (%s) cannot be read"
                    " (%s): cannot establish when libvirt loaded the secrets; its"
                    " guests are not compared" % (container, files, why),
                )
            )
            continue
        cutoff = max([c["mtime"]] + list(times.values()))
        out.append(
            _row(
                "secrets",
                host,
                "passed",
                "libvirt loaded the secrets ("
                + files
                + ") at "
                + time.strftime(UTC_FORMAT, time.gmtime(cutoff))
                + ", the later of kolla's copies in "
                + secrets_dir
                + " and the "
                + container
                + " container's",
            )
        )
        out.extend(_processes(ps_of.get(host), host, cutoff))
    return out


# The report and the printed results


def _failed(rows, ok):
    return "failed" if [x for x in rows if x["result"] not in ok] else "passed"


def cephx_validator_tests(
    pending,
    old,
    monitor,
    checkout,
    guests,
    aes_allowed,
    strict,
    checkout_dir,
    compute_hosts,
):
    """The report's tests: per check its name, result, note and rows.

    old-key-type fails only with strict (ceph_validate_strict, a bool) or
    when aes is not allowed; checkout_dir names the checkout in its note
    (None: configuration_directory is not set); running-guests is skipped
    without compute_hosts.
    """
    return [
        {
            "name": "pending-keys",
            "result": "failed" if pending else "passed",
            "note": "No entity has a pending key (a pending key is a rotation that is not finished).",
            "data": pending,
        },
        {
            "name": "old-key-type",
            "result": "failed" if old and (strict or not aes_allowed) else "passed",
            "note": "No entity's key in force is of the old type aes. Keys of that type are listed,"
            " but fail the check only with ceph_validate_strict true or when"
            " auth_allowed_ciphers excludes aes (it "
            + ("allows" if aes_allowed else "excludes")
            + " aes).",
            "data": old,
        },
        {
            "name": "monitor-copies",
            "result": _failed(monitor, ["matches"]),
            "note": "Every /etc/ceph/ceph.<entity>.keyring on the monitor hosts holds the key in force next.",
            "data": monitor,
        },
        {
            "name": "checkout",
            "result": _failed(checkout, ["matches", "no-entity"]),
            "note": "Every keyring file in %s holds the key in force next and is"
            " unmodified in git."
            % ("the checkout" if checkout_dir is None else checkout_dir),
            "data": checkout,
        },
        {
            "name": "running-guests",
            "result": (
                "skipped"
                if not compute_hosts
                else _failed(guests, ["passed", "skipped"])
            ),
            "note": (
                "no compute hosts (inventory group compute): nothing to check"
                if not compute_hosts
                else "Every QEMU process on the compute nodes started after libvirt loaded the current secrets."
            ),
            "data": guests,
        },
    ]


def cephx_validator_lines(tests):
    """The printed results: per test a line with its result and note, then a
    line per row that did not match or pass."""
    out = []
    for t in tests:
        out.append(t["name"] + ": " + t["result"] + " (" + t["note"].strip() + ")")
        for x in t["data"]:
            if x["result"] not in ("matches", "passed"):
                out.append(
                    "  "
                    + x["entity"]
                    + " @ "
                    + x["location"]
                    + ": "
                    + x["result"]
                    + ((" - " + x["note"]) if x["note"] else "")
                )
    return out


# The keyrings of the compared entities


def cephx_auth_get_failed(registered):
    """The failed reads of the loop of `ceph auth get <entity>`, a sentence
    each ("ceph auth get <entity> failed (rc N): <stderr, masked>."), ''
    if none failed. Reads rc and stderr only: stdout is the keyring."""
    return _loop_failures(registered, "ceph auth get", lambda i: i)


class FilterModule:
    def filters(self):
        return {
            f.__name__: _guarded(f.__name__)(f)
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
            )
        }
