"""Filters and helpers shared by the cephx filter plugins.

cephx_mask masks key-shaped tokens in command output before it is shown.
cephx_failed describes a command that failed, for the plays' own messages.
cephx_auth_export reads `ceph auth export -f json` down to names and flags,
nothing that carries a key.

The helpers (the names starting with _) and the constants (FSID,
STAGED_CLASSES, ROTATED_CLASSES) are the one home of what the other
plugins (cephx_rotate, cephx_redeploy, cephx_rotate_texts, cephx_validate)
share. Ansible loads each filter plugin file under a name of its own, so a
sibling cannot be imported by its name: each of them loads this file by
its path (its _load_common), once, under the one module name
_cephx_common.

The input boundary, the same in every cephx plugin: the operator's values
are checked once, by the play's input check; the results of the commands
and modules are checked where they are first read. _state sorts a
registered result by its envelope, _cmd and _loop check command results
and loop results, _records parses a command's JSON and checks the fields a
decision needs (_check_fields), _read judges a read (it ran, its rc, its
stdout), and _failure describes a command that failed (rc, stderr masked).
Output of an unexpected shape stops the play with an AnsibleFilterError
naming the command or field, never the output; the facts the plays built
with these filters are read as they are. Text from commands (stderr,
module messages) is masked with cephx_mask before it is shown. _guarded
wraps every filter so that an exception from plain Python stops the play
naming the filter and the exception's type, never its message.

No error message of a cephx plugin contains its input: the input can carry
keys.
"""

import functools
import json
import re
from collections.abc import Mapping

from ansible.errors import AnsibleFilterError

# Key-shaped tokens: Ceph's own error messages can contain a key. An aes key
# is AQ[A-D] and 37 more characters, an aes256k key Ag[A-D] and 57 more (the
# third character carries bits of the key's creation time). Not part of a
# longer base64 token.
KEY_PATTERN = (
    r"(?<![A-Za-z0-9+/])"
    r"(AQ[A-D][A-Za-z0-9+/]{35}==|Ag[A-D][A-Za-z0-9+/]{56}=)"
    r"(?![A-Za-z0-9+/=])"
)
_KEY = re.compile(KEY_PATTERN)


def cephx_mask(text):
    """Return text with every key token replaced by `<key>`."""
    if not isinstance(text, str):
        text = str(text)
    return _KEY.sub("<key>", text)


# A cluster fsid, as `ceph fsid` prints it.
FSID = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
# The classes whose keys are staged, and those rotated at once.
STAGED_CLASSES = ("openstack", "admin")
ROTATED_CLASSES = ("crash", "rgw", "bootstrap")


# The input boundary


def _guarded(name):
    """Decorator for a filter: an exception that is not an AnsibleFilterError
    becomes one naming the filter and the exception's type. Neither the
    exception's message nor the exception itself goes along: a ValueError
    of int() or strptime quotes its input, which can carry a key."""

    def wrap(func):
        @functools.wraps(func)
        def guarded(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except AnsibleFilterError:
                raise
            except Exception as e:
                kind = type(e).__name__
            # Raised outside the except block: no __context__ either.
            raise AnsibleFilterError(
                "%s: unexpected input (%s)" % (name, kind)
            ) from None

        return guarded

    return wrap


def _flag(result, flag):
    value = result.get(flag, False)
    if not isinstance(value, bool):
        raise AnsibleFilterError("a registered result's %s is not a bool" % flag)
    return value


def _state(result):
    """The envelope of a registered result: "skipped", "unreachable",
    "failed" (the module or command said so) or "ok". With
    `failed_when: false` a command that failed is "ok": its rc decides,
    which is the caller's check."""
    if not isinstance(result, Mapping):
        raise AnsibleFilterError("a registered result is not a mapping")
    for state in ("skipped", "unreachable", "failed"):
        if _flag(result, state):
            return state
    return "ok"


def _cmd(result, what):
    """A command's result, after checking that it ran (not skipped, host
    not unreachable) and has rc (int), stdout (str) and stderr (str or
    None). Whether it failed is the caller's check of rc."""
    if not isinstance(result, Mapping):
        raise AnsibleFilterError("%s: the result is not a mapping" % what)
    state = _state(result)
    if state == "skipped":
        raise AnsibleFilterError("%s: the command was skipped" % what)
    if state == "unreachable":
        raise AnsibleFilterError("%s: the host was unreachable" % what)
    for field in ("rc", "stdout"):
        if field not in result:
            raise AnsibleFilterError("%s: the result has no %s" % (what, field))
    if not _is(result["rc"], int):
        raise AnsibleFilterError("%s: rc is not an int" % what)
    if not isinstance(result["stdout"], str):
        raise AnsibleFilterError("%s: stdout is not a str" % what)
    if not isinstance(result.get("stderr"), (str, type(None))):
        raise AnsibleFilterError("%s: stderr is not a str" % what)
    return result


def _loop(registered, what):
    """The results of a registered loop task, each a mapping with its
    item."""
    if not isinstance(registered, Mapping):
        raise AnsibleFilterError("%s: the result is not a mapping" % what)
    if "results" not in registered:
        raise AnsibleFilterError("%s: the result has no results" % what)
    results = registered["results"]
    if not isinstance(results, list):
        raise AnsibleFilterError("%s: the results are not a list" % what)
    for r in results:
        if not isinstance(r, Mapping):
            raise AnsibleFilterError("%s: a result is not a mapping" % what)
        if "item" not in r:
            raise AnsibleFilterError("%s: a result has no item" % what)
    return results


def _failure(result):
    """'failed (rc N): <stderr, trimmed and masked>' ('failed (rc N)'
    without stderr) if the command (checked by _cmd) failed, else None."""
    if result["rc"] == 0:
        return None
    stderr = (result.get("stderr") or "").strip()
    if not stderr:
        return "failed (rc %d)" % result["rc"]
    return "failed (rc %d): %s" % (result["rc"], cephx_mask(stderr))


def _read(result, what, check):
    """The refusal of a read: '<what> <why>.', why being _failure's text if
    the command (a registered result, checked by _cmd) failed, else what
    check (stdout -> a reason, '' if fine) finds; '' when both are fine."""
    r = _cmd(result, what)
    why = _failure(r) or check(r["stdout"])
    return "%s %s." % (what, why) if why else ""


def _loop_failures(registered, what, name_of):
    """The commands of a loop (registered, named what) that failed, a
    sentence each ('<what> <name_of(item)> failed (rc N): <stderr>.'), ''
    if none failed. Reads rc and stderr only."""
    return " ".join(
        e
        for e in (
            _read(r, "%s %s" % (what, name_of(r["item"])), lambda stdout: "")
            for r in _loop(registered, what)
        )
        if e
    )


def _fsid(stdout):
    """A check of _read for `ceph fsid`: it printed an fsid."""
    return "" if FSID.match(stdout.strip()) else "did not print an fsid"


def _keyring_of(entity):
    """A check of _read for `ceph auth get <entity>`: its first line is
    [<entity>]."""

    def check(stdout):
        if stdout.splitlines()[:1] == ["[%s]" % entity]:
            return ""
        return "did not return the keyring of the entity"

    return check


def cephx_failed(result, what):
    """_failure of a command (a registered result, checked as _cmd does,
    named by what); '' if it exited 0."""
    return _failure(_cmd(result, what)) or ""


def _is(value, types):
    """isinstance, except that a bool is not an int (JSON's true is not 1)."""
    types = types if isinstance(types, tuple) else (types,)
    if isinstance(value, bool) and bool not in types:
        return False
    return isinstance(value, types)


def _a(types):
    """The name of a type (or of types, joined by or) with its article."""
    names = " or ".join(
        t.__name__ for t in (types if isinstance(types, tuple) else (types,))
    )
    return ("an " if names[0] in "aeiou" else "a ") + names


def _check_fields(entry, fields, what, whose):
    """entry has each field of fields (field -> type, or a tuple of types)
    with that type; whose names the entry in the message."""
    for field, types in fields.items():
        if field not in entry:
            raise AnsibleFilterError("%s: %s has no %s" % (what, whose, field))
        if not _is(entry[field], types):
            raise AnsibleFilterError("%s: %s is not %s" % (what, field, _a(types)))


def _records(text, what, shape, required):
    """A command's JSON output of the shape list (of objects) or dict (one
    object), each object having the fields of required (a mapping field ->
    type, or a tuple of types) with those types."""
    try:
        value, parsed = json.loads(text), True
    except (TypeError, ValueError):
        parsed = False
    # Refused outside the except block: the error carries no context
    # (json's message quotes the text).
    if not parsed:
        raise AnsibleFilterError("%s: did not print JSON" % what)
    if not isinstance(value, shape):
        raise AnsibleFilterError(
            "%s: did not print a JSON %s"
            % (what, "list" if shape is list else "object")
        )
    entries, whose = (value, "an entry") if shape is list else ([value], "the object")
    for e in entries:
        if not isinstance(e, dict):
            raise AnsibleFilterError("%s: an entry is not an object" % what)
        _check_fields(e, required, what, whose)
    return value


def _openstack_key_names(openstack_keys):
    """The names of the entries of openstack_keys (a site variable): a
    list of mappings, each with a name."""
    if not isinstance(openstack_keys, list):
        raise AnsibleFilterError("openstack_keys is not a list")
    for k in openstack_keys:
        if not isinstance(k, Mapping) or not isinstance(k.get("name"), str):
            raise AnsibleFilterError("openstack_keys: an entry has no name")
    return [k["name"] for k in openstack_keys]


def _osd_map(result, fields):
    """The entries of osds in `ceph osd dump -f json` (result: its
    registered result), each an object with the fields of fields (as
    _check_fields checks them)."""
    what = "ceph osd dump"
    dump = _records(_cmd(result, what)["stdout"], what, dict, {"osds": list})
    for e in dump["osds"]:
        if not isinstance(e, dict):
            raise AnsibleFilterError("%s: an entry of osds is not an object" % what)
        _check_fields(e, fields, what, "an entry of osds")
    return dump["osds"]


# The filter of `ceph auth export`


def _auth_export_entries(stdout):
    try:
        parsed = json.loads(stdout)
    except (TypeError, ValueError):
        return None
    if isinstance(parsed, dict):
        if "auth" in parsed:
            return parsed["auth"]
        return parsed.get("auth_dump", [])
    return parsed


def cephx_auth_export(stdout):
    """Map each entity of `ceph auth export -f json` to its flags.

    pending: it has a pending key. aes: the key in force next (the pending
    key if there is one, else the active key) is of type 1. Takes the `auth`
    list of a mapping, else its `auth_dump` list, or a bare list.
    """
    entries = _auth_export_entries(stdout)
    if not isinstance(entries, list) or not all(
        isinstance(e, dict) and isinstance(e.get("entity"), str) for e in entries
    ):
        raise AnsibleFilterError("ceph auth export did not print JSON")
    out = {}
    for e in entries:
        pending = e.get("pending_key") or ""
        next_key = pending or e.get("key") or ""
        out[e["entity"]] = {
            "pending": pending != "",
            "aes": isinstance(next_key, str) and next_key.startswith("AQ"),
        }
    return out


class FilterModule:
    def filters(self):
        return {
            f.__name__: _guarded(f.__name__)(f)
            for f in (
                cephx_mask,
                cephx_failed,
                cephx_auth_export,
            )
        }
