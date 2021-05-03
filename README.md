# Ansible playbooks

![Check ansible syntax](https://github.com/osism/ansible-playbooks/workflows/Check%20ansible%20syntax/badge.svg)
![Check yaml syntax](https://github.com/osism/ansible-playbooks/workflows/Check%20yaml%20syntax/badge.svg)

All Ansible playbooks for the individual Ansible container images are stored in this repository.

## Export of AWX templates

```
docker exec -it manager_awx-task_1 awx export --workflow_job_templates ID
```

```
--users [USERS]
--organizations [ORGANIZATIONS]
--teams [TEAMS]
--credential_types [CREDENTIAL_TYPES]
--credentials [CREDENTIALS]
--notification_templates [NOTIFICATION_TEMPLATES]
--projects [PROJECTS]
--inventory [INVENTORY]
--inventory_sources [INVENTORY_SOURCES]
--job_templates [JOB_TEMPLATES]
--workflow_job_templates [WORKFLOW_JOB_TEMPLATES]
```
