# AISRF on Kubernetes (plain manifests)

Single-replica deployment with a PersistentVolumeClaim for the SQLite database and logs.
For several replicas use the external PostgreSQL URL in `secret.example.yaml` and a
`ReadWriteMany` volume (or no volume, logs go to stdout as JSON lines) and read
`docs/DEPLOYMENT.md` (Scaling) first. The Helm chart in `deploy/helm/aisrf` renders the same
objects with values.

```bash
kubectl create namespace aisrf
cp secret.example.yaml secret.yaml       # fill in real values, never commit it
kubectl -n aisrf apply -f secret.yaml -f pvc.yaml -f deployment.yaml -f service.yaml
kubectl -n aisrf apply -f ingress.example.yaml   # optional, after editing the host
kubectl -n aisrf apply -f hpa.yaml               # optional, PostgreSQL only
kubectl -n aisrf rollout status deploy/aisrf
kubectl -n aisrf port-forward svc/aisrf 8080:8080
```

Generate the secrets:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'   # AISRF_SECRET_KEY
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'   # AISRF_ADMIN_API_TOKEN
```

Upgrade: `kubectl -n aisrf set image deploy/aisrf aisrf=ghcr.io/keyuraghao/aisrf:<version>`.
Uninstall: `kubectl delete namespace aisrf` (this deletes the PVC and the database).
