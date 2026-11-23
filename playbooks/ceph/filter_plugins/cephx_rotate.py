"""The decisions of cephadm-rotate-keys before any key changes.

cephx_rotate_tokens reads ceph_rotate_keys, cephx_rotate_min_age reads
ceph_rotate_keys_min_age. The checks come in three stages, as the play runs
them: the input (cephx_rotate_input_refusal), before any Ceph command; the
cluster read (cephx_rotate_read_refusal, after `ceph auth export`) and the
classification (cephx_rotate_class_refusal), before the plan is printed;
the hosts and the checkout (cephx_rotate_host_refusal, one call per check),
after it. Each returns the first refusal of its stage, in the play's order
and with its text, or ''. cephx_rotate_classify and cephx_rotate_plan give
the entities to rotate and how.

The play builds ctx once, before the classification:
  tokens          the entries of ceph_rotate_keys (names only, checked)
  openstack_keys  the names of openstack_keys, in their order
                  (cephx_rotate_openstack_names)
  existing        the entities of the cluster (ceph auth export)
  keywords        what each keyword names, for the messages
  configuration_directory  the manager's checkout

What happens once keys change is in cephx_rotate_texts (the summary and
the failure message).

The input is checked as cephx_common says; the operator's values by the
input refusal. The registered results read here carry no keys, except the
stdout of `ceph auth export`, which is only tested for its first
character.
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
_is = _common._is
_loop = _common._loop
_openstack_key_names = _common._openstack_key_names
_read = _common._read
_state = _common._state

UNCHANGED = "Nothing was changed."
KEYWORDS = ("openstack",)
# The classes of the entities other than the OpenStack keys and
# client.admin, in this order, with the prefix of their entity names.
PREFIXES = {
    "crash": "client.crash.",
    "rgw": "client.rgw.",
    "bootstrap": "client.bootstrap-",
    "lockbox": "client.osd-lockbox.",
}
# The classes this play recognises and refuses: the keywords crash, rgw,
# bootstrap and lockbox each stay one entry of their class.
NOT_HANDLED = ("crash", "rgw", "bootstrap", "lockbox")
NAME = re.compile(r"[A-Za-z0-9._-]+")
# Up to 9 digits: hours, never near int()'s limit on digits.
DIGITS = re.compile(r"[0-9]{1,9}")
# The longest value a refusal shows: a key is 40 characters or more, so a
# shorter text cannot hold one, whatever it is glued to.
SHOWN = 24
CEPH_DAEMON = re.compile(r"(mon|mgr|osd|mds)[.]")


def _class_by_prefix(name):
    """The class of PREFIXES whose prefix the name has, else None."""
    for cls, prefix in PREFIXES.items():
        if name.startswith(prefix):
            return cls
    return None


# Stage 1: the input


def cephx_rotate_tokens(value):
    """The entries of ceph_rotate_keys: a comma-separated string or a list.
    Entries are trimmed and empty ones dropped; an entry that is not a str
    (and a value that is neither a str nor a list) becomes '', which the
    input check counts as not a name."""
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, list):
        items = value
    else:
        items = [value]
    out = []
    for i in items:
        if not isinstance(i, str):
            out.append("")
        elif i.strip():
            out.append(i.strip())
    return out


def _min_age(value):
    """ceph_rotate_keys_min_age as hours: a non-negative int or a string of
    digits; None for anything else (a bool, a float, a negative number,
    other text)."""
    if _is(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and DIGITS.fullmatch(value):
        return int(value)
    return None


def _quoted(value):
    """A value of the operator's as JSON shows it (a string quoted, None
    as null), if it is short; a longer one is not shown, in case it holds a
    key given by mistake."""
    try:
        text = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return "a value of type " + type(value).__name__
    if len(text) > SHOWN:
        return "a longer value (not shown, in case it is a key)"
    return text


def cephx_rotate_input_refusal(tokens, min_age):
    """The first refusal of the input: entries that are not names (counted,
    not shown: one may be a key), no entries, an invalid min_age."""
    bad = [t for t in tokens if not NAME.fullmatch(t)]
    if bad:
        return (
            "ceph_rotate_keys takes entity names and keywords only, for example"
            " ceph_rotate_keys=client.glance or"
            " ceph_rotate_keys=client.cinder,client.nova; %d of its entries %s"
            " not (not shown, in case it is a key). Keys are generated by the"
            " monitors; this play takes none. %s"
            % (len(bad), "is" if len(bad) == 1 else "are", UNCHANGED)
        )
    if not tokens:
        return (
            "Set ceph_rotate_keys to the entities to rotate, for example osism"
            " apply cephadm-rotate-keys -e ceph_rotate_keys=client.glance. " + UNCHANGED
        )
    if _min_age(min_age) is None:
        return (
            "ceph_rotate_keys_min_age is a number of hours (default 24; 0"
            " disables the check), not %s. %s" % (_quoted(min_age), UNCHANGED)
        )
    return ""


def cephx_rotate_min_age(value):
    """ceph_rotate_keys_min_age as an int, once the input refusal has let
    it pass ("0024" is 24)."""
    hours = _min_age(value)
    if hours is None:
        raise AnsibleFilterError("ceph_rotate_keys_min_age is not a number of hours")
    return hours


# Stage 2: the cluster read


def _unchanged(*refusals):
    """The refusals joined, and that nothing was changed; '' without any."""
    errs = [e for e in refusals if e]
    return " ".join(errs) + " " + UNCHANGED if errs else ""


def _starts(first, why="did not print JSON"):
    """A check of _read: the trimmed stdout starts with first (a str or a
    tuple of them)."""
    return lambda stdout: "" if stdout.strip().startswith(first) else why


def _read_auth_export(result):
    check = _starts(("{", "["), "failed to print JSON")
    return _unchanged(_read(result, "ceph auth export", check))


READS = {
    "auth_export": _read_auth_export,
}


def cephx_rotate_read_refusal(name, result):
    """The refusal after the cluster read `name` (a key of READS): the
    command failed or printed no JSON."""
    if name not in READS:
        raise AnsibleFilterError("cephx_rotate_read_refusal: no read %s" % name)
    return READS[name](result)


# Stage 2: the classification


def cephx_rotate_openstack_names(openstack_keys):
    """The names of the entries of openstack_keys, for ctx: a value that is
    not a list, or an entry without a name, stops."""
    return _openstack_key_names(openstack_keys)


def _openstack_names(ctx):
    """The entries of openstack_keys that are rotated as OpenStack keys: not
    client.admin, nor an entity of another class."""
    return [
        n
        for n in ctx["openstack_keys"]
        if n != "client.admin" and _class_by_prefix(n) is None
    ]


def _class_of(name, openstack):
    if name == "client.admin":
        return "admin"
    cls = _class_by_prefix(name)
    if cls:
        return cls
    if name in openstack:
        return "openstack"
    if CEPH_DAEMON.match(name):
        return "daemon"
    return "unknown"


def _keyword_names(keyword, ctx, openstack):
    # openstack, the one keyword handled
    return [n for n in openstack if n in ctx["existing"]]


def cephx_rotate_classify(tokens, ctx):
    """Each entity named, with its class and the keyword that named it ('' for
    a name given as such). The keyword openstack stands for the entries of
    openstack_keys that exist. The keyword of a class not handled (crash,
    rgw, bootstrap, lockbox) stays one entry of its class, refused."""
    openstack = _openstack_names(ctx)
    out = []
    for t in tokens:
        if t in KEYWORDS:
            out.extend(
                {"name": n, "class": t, "keyword": t}
                for n in _keyword_names(t, ctx, openstack)
            )
        elif t in NOT_HANDLED:
            out.append({"name": t, "class": t, "keyword": t})
        else:
            out.append({"name": t, "keyword": "", "class": _class_of(t, openstack)})
    return out


def cephx_rotate_skipped(tokens, ctx):
    """The OpenStack keys the keyword openstack skipped: not on the cluster."""
    if "openstack" not in tokens:
        return []
    return [n for n in _openstack_names(ctx) if n not in ctx["existing"]]


def _names_of(classified, *classes):
    return [c["name"] for c in classified if c["class"] in classes]


def _refuse_ceph_daemons(classified, ctx):
    names = _names_of(classified, "daemon")
    if names:
        return (
            "%s: the keys of Ceph daemons (mon., mgr.*, osd.*, mds.*) are rotated"
            " by cephadm's upgrade, not by this play. %s"
            % (", ".join(names), UNCHANGED)
        )
    return ""


def _refuse_unknown(classified, ctx):
    names = _names_of(classified, "unknown")
    if names:
        return (
            "%s: not a key this play rotates. It takes the keyword openstack, the"
            " entries of openstack_keys (%s) and client.admin. Tenant keys"
            " (Manila) are rotated through Manila's access rules. %s"
            % (", ".join(names), ", ".join(ctx["openstack_keys"]), UNCHANGED)
        )
    return ""


def _refuse_not_handled(classified, ctx):
    names = _names_of(classified, *NOT_HANDLED)
    if names:
        return "%s: not handled by this play (classes %s). %s" % (
            ", ".join(names),
            ", ".join(NOT_HANDLED),
            UNCHANGED,
        )
    return ""


def _refuse_twice(classified, ctx):
    tokens = ctx["tokens"]
    named = [t for t in tokens if t in KEYWORDS] + [c["name"] for c in classified]
    twice = list(dict.fromkeys(n for n in named if named.count(n) > 1))
    if not twice:
        return ""
    keywords = ctx["keywords"]
    used = [k for k in keywords if k in tokens]
    why = (
        " (%s)"
        % "; ".join("the keyword %s includes %s" % (k, keywords[k]) for k in used)
        if used
        else ""
    )
    return "ceph_rotate_keys names an entity more than once: %s%s. %s" % (
        ", ".join(twice),
        why,
        UNCHANGED,
    )


def _refuse_cinder_alone(classified, ctx):
    names = [c["name"] for c in classified]
    if ("client.cinder" in names) != ("client.nova" in names):
        return (
            "client.cinder and client.nova must be rotated together"
            " (ceph_rotate_keys=client.cinder,client.nova): Nova uses both, and"
            " every running guest is migrated after their rotation. " + UNCHANGED
        )
    return ""


def _refuse_missing(classified, ctx):
    existing = ctx["existing"]
    names = [c["name"] for c in classified if c["name"] not in existing]
    if names:
        return (
            "%s: does not exist on the cluster (ceph auth export). This play"
            " gives existing entities new keys; cephadm-pools creates the keys of"
            " openstack_keys. %s" % (", ".join(names), UNCHANGED)
        )
    return ""


# In the play's order: the first that applies is the refusal.
CLASS_CHECKS = (
    _refuse_ceph_daemons,
    _refuse_unknown,
    _refuse_not_handled,
    _refuse_twice,
    _refuse_cinder_alone,
    _refuse_missing,
)


def cephx_rotate_class_refusal(classified, ctx):
    """The first refusal of the classification, or ''."""
    for check in CLASS_CHECKS:
        refusal = check(classified, ctx)
        if refusal:
            return refusal
    return ""


# The plan


def cephx_rotate_plan(classified, ctx):
    """The plan: entities ({name, class}, in order), each staged (the
    OpenStack keys and client.admin)."""
    entities = [{"name": c["name"], "class": c["class"]} for c in classified]
    return {"entities": entities}


# Stage 3: the hosts and the checkout, after the printed plan


def _stat_flag(stat, key, what):
    if key not in stat:
        raise AnsibleFilterError("%s: the stat has no %s" % (what, key))
    if not isinstance(stat[key], bool):
        raise AnsibleFilterError("%s: the stat's %s is not a bool" % (what, key))
    return stat[key]


def _host_monitors(result, ctx):
    """/etc/ceph on the monitor hosts (the stat loop; a skipped item was not
    checked): an existing /etc/ceph that is not a directory, then one that
    is not writable. A missing one is created when the keyrings are
    written."""
    what = "the monitor hosts"
    not_dirs, not_writable = [], []
    for r in _loop(result, what):
        state = _state(r)
        if state == "skipped":
            continue
        if state != "ok":
            raise AnsibleFilterError("%s: the stat %s" % (what, state))
        stat = r.get("stat")
        if not isinstance(stat, Mapping):
            raise AnsibleFilterError("%s: the result has no stat" % what)
        if not _stat_flag(stat, "exists", what):
            continue
        if not _stat_flag(stat, "isdir", what):
            not_dirs.append(r["item"])
        elif not _stat_flag(stat, "writeable", what):
            not_writable.append(r["item"])
    hosts = not_dirs + not_writable
    if hosts:
        return "/etc/ceph is not a writable directory on %s. %s" % (
            ", ".join(hosts),
            UNCHANGED,
        )
    return ""


def _host_configuration_directory(result, ctx):
    """{staged, defined}: configuration_directory is needed for the staged
    keys; defined is false when it is unset or null."""
    if result["staged"] and not result["defined"]:
        return (
            "configuration_directory (the manager's checkout of the configuration"
            " repository) is not set. " + UNCHANGED
        )
    return ""


def _host_checkout_places(result, ctx):
    placed = [c["name"] for c in result["checked"]]
    names = [s["name"] for s in result["staged"] if s["name"] not in placed]
    if names:
        return (
            "%s: no directory for its keyring in the configuration repository's"
            " checkout (%s; copy-ceph-keys writes to the same places,"
            " ceph_custom_keys adds more). If the service is not run, delete the"
            " key (ceph auth del <name>) instead of rotating it. %s"
            % (", ".join(names), ctx["configuration_directory"], UNCHANGED)
        )
    return ""


def _host_checkout_writable(result, ctx):
    """The directories of the checkout that are missing, then those that
    cannot be written, each named once."""
    missing = [os.path.dirname(c["dest"]) for c in result if not c["exists"]]
    locked = [os.path.dirname(c["dest"]) for c in result if not c["writeable"]]
    dirs = list(dict.fromkeys(missing + locked))
    if dirs:
        return (
            "%s cannot be written (a directory for the keyrings in the checkout). %s"
            % (", ".join(dirs), UNCHANGED)
        )
    return ""


HOST_CHECKS = {
    "monitors": _host_monitors,
    "configuration_directory": _host_configuration_directory,
    "checkout_places": _host_checkout_places,
    "checkout_writable": _host_checkout_writable,
}


def cephx_rotate_host_refusal(name, result, ctx):
    """The refusal of the host check `name` (a key of HOST_CHECKS) on its
    result, or ''."""
    if name not in HOST_CHECKS:
        raise AnsibleFilterError("cephx_rotate_host_refusal: no check %s" % name)
    return HOST_CHECKS[name](result, ctx)


class FilterModule:
    def filters(self):
        return {
            f.__name__: _guarded(f.__name__)(f)
            for f in (
                cephx_rotate_tokens,
                cephx_rotate_input_refusal,
                cephx_rotate_min_age,
                cephx_rotate_openstack_names,
                cephx_rotate_read_refusal,
                cephx_rotate_classify,
                cephx_rotate_skipped,
                cephx_rotate_class_refusal,
                cephx_rotate_plan,
                cephx_rotate_host_refusal,
            )
        }
