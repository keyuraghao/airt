# Deployment assets

| Path | Purpose |
| --- | --- |
| `systemd/` | Linux service unit with hardening and an install README (`EnvironmentFile=/etc/aisrf/aisrf.env`, dedicated user). |
| `launchd/` | macOS launch agent / daemon plist. |
| `windows/` | `install-service.ps1` (NSSM or `sc.exe` + wrapper) and `uninstall-service.ps1`. |
| `kubernetes/` | Plain manifests: Deployment, Service, PVC, Secret example, Ingress example, HPA. |
| `helm/aisrf/` | Helm chart (image `ghcr.io/keyuraghao/aisrf`, Secret-backed env, persistence, ingress, probes, optional PostgreSQL URL, HPA). |

The full install matrix, first-run security notes, upgrade and uninstall steps are in
[docs/INSTALL.md](../docs/INSTALL.md).
