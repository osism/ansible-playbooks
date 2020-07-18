#!/usr/bin/env python3

import json
import subprocess

from ansible.module_utils.basic import AnsibleModule
from yaml import safe_load as yaml_safe_load

DOCUMENTATION = '''
---
module: osquery
short_description: Get data from osquery
description:
    - Get data from osquery
options:
    query:
        required: true
        description:
            - Query to run
        type: str
author: "Christian Berendt (@berendt)"
'''

EXAMPLES = '''
- hosts: all
  tasks:
    - name: Get all processes
      osquery:
        query: "SELECT * FROM processes"
      register: result
'''


def main():
    module = AnsibleModule(
        argument_spec=yaml_safe_load(DOCUMENTATION)['options']
    )

    query = module.params.get('query')
    cmd = ['/usr/bin/osqueryi', '--json', query]

    try:
        result = subprocess.check_output(cmd, universal_newlines=True).strip()
    except subprocess.CalledProcessError as e:
        module.fail_json(msg="Failed to run osquery: {}".format(e.output))

    module.exit_json(changed=False, resultset=json.loads(result))


if __name__ == '__main__':
    main()
