"""The texts of cephadm-rotate-keys once keys change: the failure message
of the rescue (cephx_rotate_failure) and the summary with the next steps
(cephx_rotate_summary).

Both read the entries of _rotate_keys_done, one per entity handled, as the
task file writes them:
  {name, class, action, checkout, monitors}, the class openstack or admin

The plays build these entries with their own filters, so they are read as
they are: a missing field or an unknown class or action is a bug in the
play and stops it (an AnsibleFilterError naming the filter). The
failure message is plain sentences, one space between them. No entry
carries a key.
"""

import importlib.util
import os
import sys

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
STAGED_CLASSES = _common.STAGED_CLASSES

GUESTS = ("client.cinder", "client.nova")
USED_RARELY = ("client.glance", "client.cinder-backup")

# The actions of _set-entity-key.yml as the failure message names them.
ACTIONS = {
    "staged": "staged",
    "already_staged": "already staged",
    "skipped_recent": "no new key",
}


def _join(items):
    return ", ".join(map(str, items))


# The failure message of the rescue

AGAIN = (
    "Run the same command again: an entity staged in this run keeps its "
    "pending key (or, once committed, gets no new key before "
    "ceph_rotate_keys_min_age), and its files are written again."
)
AGAIN_MIN_AGE_0 = (
    "Run the command again, but without -e ceph_rotate_keys_min_age=0: with "
    "it, every entity committed in this run would get a new key again. "
    "Without it (the default, 24 hours): an entity staged in this run keeps "
    "its pending key (or, once committed, gets no new key), and its files are "
    "written again."
)


def _done_failure(d):
    """One entry of _rotate_keys_done as a sentence."""
    cls = d["class"]
    if cls in STAGED_CLASSES:
        return "%s: %s, written to the checkout%s." % (
            d["name"],
            ACTIONS[d["action"]],
            " and the monitor hosts" if d["monitors"] else "",
        )
    raise AnsibleFilterError("cephx_rotate_failure: an entry of an unknown class")


def _entity_failure(name, current):
    """A staged entity in progress."""
    if current["action"]:
        why = ACTIONS[current["action"]] + ", its files not all written"
    else:
        why = "its key may have been staged"
    return "%s: not finished (%s)." % (name, why)


def cephx_rotate_failure(done, current, ctx):
    """The failure message after a stop while keys change: what was done,
    what was in progress, and how the next run continues.

    current: what was in progress, as the task file notes it:
      name        _rotate_keys_current ('' between entities)
      action      _rotate_keys_current_action
    ctx: min_age (the int of the input checks).
    """
    name = current["name"]
    parts = ["The run stopped at %s (see the error above)." % (name or "an entity")]
    parts += [_done_failure(d) for d in done]
    if name:
        parts.append(_entity_failure(name, current))
    again = AGAIN_MIN_AGE_0 if ctx["min_age"] == 0 else AGAIN
    parts.append(again)
    return " ".join(parts)


# The summary and the next steps

STAGED = "staged"
ALREADY_STAGED = "already staged (pending key of an earlier run, the same key)"
YOUNGER = (
    "no new key: the active key is younger than %d hours "
    "(ceph_rotate_keys_min_age; 0 rotates again)"
)
NEXT_STAGED = (
    "Next steps, now and one directly after the other (staged keys are not "
    "left lying around):"
)
NEXT_COMMITTED = (
    ", if the repository or the services do not have this key yet (whoever "
    "still holds the old key cannot open new connections), now and one "
    "directly after the other:"
)
STEP_COPY = (
    "1. Copy the keyring files listed under checkout above from the "
    "manager's checkout into your configuration repository (encrypt them "
    "first if your repository keeps keyrings encrypted), commit, push, then: "
    "osism apply configuration"
)
STEP_MIGRATE = (
    "3. Directly after osism apply nova: live-migrate every running guest, "
    "for each compute node: osism manage compute migrate --yes "
    "--no-cold-migration <host> (it waits for each migration; a guest may be "
    "migrated twice, which does no harm). Shut-off guests need nothing."
)
STEP_CHECK_GUESTS = (
    "4. osism validate ceph-keys: the migrate command also reports a failed "
    "migration as completed, so this check decides. running-guests names "
    "each guest still holding the old key; live-migrate it with osism manage "
    "server migrate --yes <guest UUID>, or stop and start it if it cannot be "
    "live-migrated, and check again until none is named."
)
STEP_CHECK = "3. osism validate ceph-keys"
USED_RARELY_TEXT = (
    "client.glance and client.cinder-backup may connect to Ceph only when "
    "used: if the check still reports a pending key for one of them after its "
    "apply, upload or download an image (client.glance) or create a backup "
    "(client.cinder-backup), then check again."
)
NO_TEST_LOGIN = (
    "Do not use the staged keyring by hand (no test login with it): its first "
    "use commits it, and so does any failed login for the entity with a wrong "
    "key. From the commit on, the old key stops working, and whoever still "
    "holds it cannot open new connections until it is applied."
)
FREEZE = (
    "no monitor or OSD restart until every guest is migrated, no node reboot, "
    "no Ceph upgrade. Each would freeze the guests not yet migrated; a frozen "
    "guest needs openstack server reboot --hard (live migration does not work "
    "on it)."
)
GUESTS_STAGED = (
    "client.cinder and client.nova were staged at %s; they are committed at "
    "their first use, at the latest by osism apply cinder and osism apply "
    "nova. From that commit on: " + FREEZE
)
GUESTS_IN_FORCE = (
    "The new keys of client.cinder and client.nova are already in force. "
    "Until every running guest is migrated (step 3): " + FREEZE
)
ADMIN_STAGED = (
    "client.admin: until its commit and cephadm's next refresh, ceph and "
    "cephadm shell on the monitors cannot read their admin keyring (cephadm "
    "writes it with the pending key line), and the check reports "
    "monitor-copies failed for client.admin; run it again about ten minutes "
    "after osism apply cephclient. The manager's ceph keeps working with the "
    "old key until the commit. If the commit comes early and the manager's "
    "ceph fails: osism apply cephclient installs the staged keyring from the "
    "checkout."
)
ADMIN_IN_FORCE = (
    "client.admin: its new key is already in force. If the manager's ceph "
    "fails with the old key: osism apply cephclient installs the keyring from "
    "the checkout."
)


def _per_entity(done, ctx):
    younger = YOUNGER % ctx["min_age"]
    # The actions _set-entity-key.yml gives the staged classes.
    staged = dict(
        staged=STAGED,
        already_staged=ALREADY_STAGED,
        skipped_recent=younger
        + "; its files were written again with that key (see the next steps)",
    )
    out = []
    for d in done:
        cls, action = d["class"], d["action"]
        if cls in STAGED_CLASSES:
            out.append("%s: %s" % (d["name"], staged[action]))
            out += ["  checkout: %s" % p for p in d["checkout"]]
            if d["monitors"]:
                out.append(
                    "  monitors: /etc/ceph/ceph.%s.keyring on %s"
                    % (d["name"], _join(ctx["mons"]))
                )
        else:
            raise AnsibleFilterError(
                "cephx_rotate_summary: an entry of an unknown class"
            )
    return out if out else ["Nothing to rotate."]


def _step_apply(handled, services, staged):
    """Step 2: the services to apply, in the order of the entities."""
    unmapped = [n for n in handled if n not in services]
    applies = list(
        dict.fromkeys(s for n in handled if n in services for s in services[n])
    )
    step = ", then ".join("osism apply " + s for s in applies)
    if unmapped:
        users = "the services that use " + _join(unmapped)
        step = step + " and " + users if step else "Apply " + users
    return (
        "2. "
        + step
        + "."
        + (" The first use of a new key commits it." if staged else "")
    )


def _next_steps(done, ctx):
    done_staged = [d for d in done if d["class"] in STAGED_CLASSES]
    handled = [d["name"] for d in done_staged]
    staged = [
        d["name"] for d in done_staged if d["action"] in ("staged", "already_staged")
    ]
    committed = [d["name"] for d in done_staged if d["action"] == "skipped_recent"]
    out = []
    if handled:
        guests = any(g in handled for g in GUESTS)
        if staged:
            out.append(NEXT_STAGED)
        if committed:
            out.append(
                (
                    "For "
                    + _join(committed)
                    + ", whose new key is already in force: the same steps"
                    if staged
                    else "Next steps"
                )
                + NEXT_COMMITTED
            )
        out.append(STEP_COPY)
        out.append(_step_apply(handled, ctx["services"], staged))
        if guests:
            out.append(STEP_MIGRATE)
            out.append(STEP_CHECK_GUESTS)
        else:
            out.append(STEP_CHECK)
        if any(n in USED_RARELY for n in staged):
            out.append(USED_RARELY_TEXT)
        if staged:
            out.append(NO_TEST_LOGIN)
        if any(g in staged for g in GUESTS):
            out.append(GUESTS_STAGED % ctx["now"])
        elif guests:
            out.append(GUESTS_IN_FORCE)
        if "client.admin" in staged:
            out.append(ADMIN_STAGED)
        elif "client.admin" in handled:
            out.append(ADMIN_IN_FORCE)
    return out


def cephx_rotate_summary(done, ctx):
    """The lines of the summary: each entity done, then the next steps.

    ctx: min_age (the int of the input checks), mons (the monitor hosts),
    services (_cephx_key_services: the services to apply per entity), now
    (the time, as 'YYYY-MM-DD HH:MM UTC').
    """
    return _per_entity(done, ctx) + _next_steps(done, ctx)


class FilterModule:
    def filters(self):
        return {
            f.__name__: _guarded(f.__name__)(f)
            for f in (
                cephx_rotate_failure,
                cephx_rotate_summary,
            )
        }
