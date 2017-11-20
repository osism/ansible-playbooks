#!/usr/bin/env python

import xmlrpclib

def main():
    module = AnsibleModule(
        argument_spec = dict(
            username   = dict(required=True, no_log=True),
            password   = dict(required=True, no_log=True),
            server_url = dict(required=False, default="http://localhost/cobbler_api"),
            entity     = dict(required=False, no_log=False),
            action     = dict(required=True, no_log=False),
            params     = dict(required=False, no_log=True, type="dict"),
        )
    )

    server_url = module.params["server_url"]
    username = module.params["username"]
    password = module.params["password"]

    try:
        connection = xmlrpclib.Server(server_url)
    except Exception as e:
        module.fail_json(msg="Connection failed: %s" % e)

    try:
        token = connection.login(username, password)
    except:
        module.fail_json(msg="Authorization failed")

    action = module.params["action"]
    entity = module.params["entity"]
    params = module.params["params"]


    if action == "sync":
        try:
            result = connection.sync(token)
            module.exit_json(changed=result)
        except Exception as e:
            module.fail_json(msg="sync failed: %s" % e)
    elif action == "reposync":
        try:
            result = connection.background_reposync([], token)
            module.exit_json(changed=result)
        except Exception as e:
            module.fail_json(msg="reposync failed: %s" % e)
    elif action == "import":
        try:
            result = connection.background_import(params, token)
            module.exit_json(changed=result)
        except Exception as e:
            module.fail_json(msg="import failed: %s" % e)
    elif action == "import":
        try:
            module.exit_json(changed=result)
        except Exception as e:
            module.fail_json(msg="import failed: %s" % e)
    elif action == "get":
        try:
            result = connection.get_item(entity, params["name"])
            if result == "~":
                module.fail_json(msg="%s %s not found" % (entity, params["name"]))
            module.exit_json(ansible_facts=dict(cobbler_result=result))
        except Exception as e:
            module.fail_json(msg="get failed: %s" % e)
    elif action == "del":
        try:
            result = connection.remove_item(entity, params["name"], token)
            if result == "~":
                module.fail_json(msg="%s %s not found" % (entity, params["name"]))
            module.exit_json(ansible_facts=dict(cobbler_result=result))
        except Exception as e:
            module.fail_json(msg="del failed: %s" % e)
    elif action == "has":
        try:
            result = connection.has_item(entity, params["name"])
            module.exit_json(ansible_facts=dict(cobbler_result=result))
        except Exception as e:
            module.fail_json(msg="has failed: %s" % e)
    elif action == "new":
        try:
            object_id = connection.new_item(entity, token)
            for param in params:
                if entity == "system" and param == "interfaces":
                    connection.modify_item(entity, object_id, "modify_interface", params[param], token)
                connection.modify_item(entity, object_id, param, params[param], token)

            connection.save_item(entity, object_id, token, "new")
            module.exit_json(changed=True)
        except Exception as e:
            module.fail_json(msg="new failed: %s" % e)

    
    if entity == "distro":
        if action == "list":
            result = connection.get_distros(token)
            module.exit_json(ansible_facts=dict(cobbler_result=result))

# import module snippets
from ansible.module_utils.basic import *  # noqa

if __name__ == '__main__':
    main()
