# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.20251022.0] - 2025-10-22

### Added
- Kepler monitoring playbook for applying the kepler role

### Changed
- Moved stepca playbook from infrastructure to kolla environment

## [v0.20251013.0] - 2025-10-13

### Added
- New playbook for OpenTelemetry Collector service (`opentelemetry-collector`)
- New playbook for Step CA service (`stepca`)

## [v0.20251006.0] - 2025-10-06

### Added
- New playbook for Substation TUI (`substation`)

## [v0.20250927.0] - 2025-09-27

### Changed
- Improved Ceph keys handling in copy-ceph-keys playbook with directory existence checks before writing keys
- Replaced ignore_errors with proper file existence checks when fetching Ceph keys for cleaner error handling

## [v0.20250902.0] - 2025-09-02

### Changed
- Zuul CI configuration: removed gate pipeline, added cosign secrets for container image signing
- Bootstrap play now allows disabling smartd service via `enable_smartd` variable (defaults to true)

## [v0.20250710.0] - 2025-07-10

### Added
- New playbook for gNMIc (gRPC Network Management Interface client) (`gnmic`)

## [v0.20250619.0] - 2025-06-19

### Added
- New playbook for Docker version validation (`validate-docker-version.yml`)

## [v0.20250602.0] - 2025-06-02

### Changed
- Manager service restart now handled by the manager role's built-in handlers instead of a separate playbook task

### Added
- New playbook for Wazuh agent service (`wazuh-agent`)

### Changed
- Registry for tenks play from quay.io to registry.osism.tech
- Tenks play now displays a message indicating that the 'Run tenks' task takes some time to complete
- Zuul CI secrets refreshed

## [v0.20250428.0] - 2025-04-28

### Removed
- Kubernetes-monitoring playbook (moved to osism/osism-kubernetes)

## [v0.20250407.0] - 2025-04-07

### Added
- New playbook running stress validations (`validate-stress`)

### Removed
- Rook playbooks (moved to osism/osism-kubernetes)
- K3s playbooks (moved to osism/osism-kubernetes)
- Kubernetes playbooks including kubeconfig and kubernetes-label-nodes (moved to osism/osism-kubernetes)
- Clusterapi playbook (moved to osism/osism-kubernetes)
- Cloudnative_pg play (moved to osism/osism-kubernetes)
- Kubectl playbook (moved to osism/osism-kubernetes)
- K9s playbook (moved to osism/osism-kubernetes)

## [v0.20250314.0] - 2025-03-14

### Added
- Share directory creation task in copy-ceph-keys play to ensure directory exists before copying keys

### Changed
- File permissions for ceph keys in copy-ceph-keys play from 0644 to 0640 for improved security

## [v0.20250219.0] - 2025-02-19

### Added
- New playbook for deploying containerlab wrapper script and clab symlink (`containerlab`)
- New playbook for Dnsmasq (`dnsmasq`)
- New playbook for Httpd (`httpd`)
- New playbook for testing baremetal deployments in virtualized environments (`tenks`)

### Changed
- Copy-ceph-keys play now fetches Ceph keys directly from the first monitor node instead of using the ceph-ansible container, simplifying the key retrieval process

### Removed
- Old keycloak plays (keycloak.yml and keycloak-oidc-client-config.yml)
- Virtualbmc play

## [v0.20241219.0] - 2024-12-19

### Added
- Play to run specific DebOps roles (`debops`)
