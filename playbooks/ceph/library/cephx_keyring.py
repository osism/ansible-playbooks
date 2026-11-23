#!/usr/bin/python

import base64
import binascii
import hashlib
import re
import struct

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = """
---
module: cephx_keyring
short_description: Inspect a Ceph keyring without exposing its keys
description:
    - Parses the output of C(ceph auth get) (or a keyring file) and reports
      key type, creation time and fingerprints of the C(key) and of the
      C(pending key) while a key rotation is staged.
    - Keys are never returned, except in C(normalised_lines) on request.
options:
    keyring:
        description:
            - Keyring text. Mutually exclusive with I(path).
        type: str
    path:
        description:
            - Keyring file on the target host. Mutually exclusive with
              I(keyring).
        type: str
    want_normalised:
        description:
            - Return as C(normalised_lines) the keyring with the key in
              force next (the pending key if present, else the key) on the
              C(key) line and no C(pending key) line. The result contains a key, so use
              C(no_log) on the task.
        type: bool
        default: false
author: "OSISM"
"""

EXAMPLES = """
- name: Read the keyring of an entity
  cephx_keyring:
    keyring: "{{ keyring_text }}"
  no_log: true
  register: result

- name: Normalise a keyring file
  cephx_keyring:
    path: /etc/ceph/ceph.client.glance.keyring
    want_normalised: true
  no_log: true
  register: result
"""

RETURN = """
entity:
    description: Entity name from the keyring header.
    type: str
    returned: success
key_type:
    description: Key type, 1 (aes) or 2 (aes256k).
    type: int
    returned: success
key_created:
    description: Key creation time in epoch seconds.
    type: int
    returned: success
key_fp:
    description: First 12 hex characters of the sha256 of the base64 key.
    type: str
    returned: success
has_pending:
    description: Whether a C(pending key) is present.
    type: bool
    returned: success
pending_type:
    description: Type of the pending key, null without one.
    type: int
    returned: success
pending_created:
    description: Creation time of the pending key, null without one.
    type: int
    returned: success
pending_fp:
    description: Fingerprint of the pending key, null without one.
    type: str
    returned: success
in_force_fp:
    description: Fingerprint of the key in force next.
    type: str
    returned: success
normalised_lines:
    description:
        - Lines of the keyring with the key in force on the C(key) line and
          no C(pending key) line, one element per line, no trailing empty
          element. Join with C(normalised_lines | join('\n') ~ '\n').
        - Returned as lines because Ansible masks any output string that
          contains the whole I(keyring) value, which a keyring without a
          pending key would equal.
    type: list
    elements: str
    returned: when want_normalised is true
"""

SECRET_LEN = {1: 16, 2: 32}
KEY_LINE = re.compile(r"^(\s*)key\s*=\s*(\S*)\s*$")
PENDING_LINE = re.compile(r"^\s*pending key\s*=\s*(\S*)\s*$")
HEADER = re.compile(r"^\[([^\]\s]+)\]\s*$")


class KeyringError(Exception):
    pass


def decode_key(value, what):
    """Return (type, created, fingerprint); never put the key in an error."""
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise KeyringError("%s is not a cephx key" % what)
    if len(raw) < struct.calcsize("<HIIH"):
        raise KeyringError("%s is not a cephx key" % what)
    key_type, sec, _nsec, length = struct.unpack(
        "<HIIH", raw[: struct.calcsize("<HIIH")]
    )
    if (
        key_type not in SECRET_LEN
        or length != SECRET_LEN[key_type]
        or len(raw) != struct.calcsize("<HIIH") + length
        or base64.b64encode(raw).decode() != value
    ):
        raise KeyringError("%s is not a cephx key" % what)
    return key_type, sec, hashlib.sha256(value.encode()).hexdigest()[:12]


def parse(text, source):
    lines = text.splitlines()
    body = [i for i, line in enumerate(lines) if line.strip()]
    match = HEADER.match(lines[body[0]]) if body else None
    if not match:
        raise KeyringError("%s is not a keyring: no [entity] header" % source)
    entity = match.group(1)
    # One entity per keyring: a key under a second header would otherwise be
    # taken as the first entity's.
    if any(line.lstrip().startswith("[") for line in lines[body[0] + 1 :]):
        raise KeyringError("%s: keyring must have exactly one [entity] header" % entity)
    keys = [i for i, line in enumerate(lines) if KEY_LINE.match(line)]
    pend = [i for i, line in enumerate(lines) if PENDING_LINE.match(line)]
    if len(keys) != 1 or len(pend) > 1:
        raise KeyringError(
            "%s: keyring must have exactly one key line and at most one "
            "pending key line" % entity
        )
    what = "key of %s" % entity
    key = KEY_LINE.match(lines[keys[0]]).group(2)
    info = {"entity": entity}
    info["key_type"], info["key_created"], info["key_fp"] = decode_key(key, what)
    info["has_pending"] = bool(pend)
    in_force = key
    info["pending_type"] = info["pending_created"] = None
    info["pending_fp"] = None
    if pend:
        in_force = PENDING_LINE.match(lines[pend[0]]).group(1)
        info["pending_type"], info["pending_created"], info["pending_fp"] = decode_key(
            in_force, "pending key of %s" % entity
        )
    info["in_force_fp"] = info["pending_fp"] or info["key_fp"]
    out = []
    for i, line in enumerate(lines):
        if pend and i == pend[0]:
            continue
        if i == keys[0]:
            line = KEY_LINE.match(line).group(1) + "key = " + in_force
        out.append(line)
    return info, out


def main():
    module = AnsibleModule(
        argument_spec=dict(
            keyring=dict(type="str", no_log=True),
            path=dict(type="str"),
            want_normalised=dict(type="bool", default=False),
        ),
        mutually_exclusive=[["keyring", "path"]],
        required_one_of=[["keyring", "path"]],
        supports_check_mode=True,
    )
    path = module.params["path"]
    if path:
        try:
            with open(path) as f:
                text = f.read()
        except (IOError, OSError) as e:
            module.fail_json(msg="cannot read %s: %s" % (path, e.strerror))
        source = path
    else:
        text = module.params["keyring"]
        source = "keyring input"
    try:
        info, normalised_lines = parse(text, source)
    except KeyringError as e:
        msg = str(e)
        if path and path not in msg:
            msg = "%s: %s" % (path, msg)
        module.fail_json(msg=msg)
    if module.params["want_normalised"]:
        info["normalised_lines"] = normalised_lines
    module.exit_json(changed=False, **info)


if __name__ == "__main__":
    main()
