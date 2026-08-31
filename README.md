# DevSecOps Platform — Infrastructure as Code

Guide de déploiement et de reproduction de la plateforme DevSecOps
(cluster Kubernetes sécurisé, CI/CD, observabilité, exposition), réalisée
dans le cadre du stage d'été 2025-2026.

📄 Rapport complet : https://fr.overleaf.com/read/rhdvqnvhjpkj#cba1d4

⚠️ Ce repo contient la **configuration**, jamais les secrets. Voir la section
[Secrets à recréer](#secrets-à-recréer) avant de commencer.

## Composants

- **Cluster** : Kind, RBAC moindre privilège, Pod Security (restricted/baseline/privileged)
- **CI/CD** : Jenkins + agents éphémères, Gitleaks, Checkov, SonarCloud, Trivy
- **Observabilité** : Prometheus, Loki, Grafana, Falco
- **Exposition** : NGINX Ingress + Cloudflare Tunnel

## Dépôts liés

- Dashboard unifié : https://github.com/RiahiAmani/devsecops-dashboard.git
- Application de test (TaskManager, contient le Jenkinsfile) : https://github.com/RiahiAmani/flask-postgres-docker-compose.git

## Prérequis

- Machine : min. 8 Go RAM, 4 vCPU, 40 Go disque, Ubuntu Server 24.04 LTS
- Docker, [Kind](https://kind.sigs.k8s.io/), kubectl, Helm 3
- Comptes : GitHub, SonarCloud, Docker Hub, Cloudflare (avec un domaine)

## Installation des dépôts Helm

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
```

## Guide de reproduction (ordre à respecter)

### 1. Créer le cluster Kind
```bash
kind create cluster --config k8s/cluster-config/kind-config.yaml
```

### 2. Créer les espaces de noms
```bash
kubectl apply -f k8s/namespaces/
```

### 3. Appliquer le RBAC (moindre privilège)
```bash
kubectl apply -f k8s/rbac/
```

### 4. Appliquer les politiques de sécurité des pods
```bash
kubectl apply -f k8s/pod-security/
```
> Test de validation inclus : `pod-privileged-test.yaml` doit être **rejeté** par l'admission.

### 5. Appliquer les NetworkPolicy
```bash
kubectl apply -f k8s/network/
```

### 6. Déployer Jenkins
```bash
kubectl apply -f ci-cd/jenkins-pvc.yaml
kubectl apply -f ci-cd/jenkins-deployment.yaml
kubectl apply -f ci-cd/jenkins-servicemonitor.yaml
```
Le pipeline (`Jenkinsfile`) est versionné dans le repo applicatif ci-dessus (Pipeline as Code).

### 7. Déployer la pile d'observabilité
```bash
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  -n monitoring --create-namespace \
  -f observability/prometheus/prometheus-stack-values.yaml

helm install loki grafana/loki-stack \
  -n monitoring \
  -f observability/loki-promtail/loki-values.yaml

kubectl apply -f observability/prometheus/node-exporter-textfile.yaml

helm upgrade kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  -n monitoring -f observability/grafana/grafana-smtp-patch.yaml
```

### 8. Déployer Falco
```bash
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set-file customRules."custom-rules\.yaml"=security/falco/falco-custom-rules.yaml
```

### 9. Exposer les services (NGINX Ingress + Cloudflare Tunnel)
```bash
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace \
  --set controller.service.type=ClusterIP

kubectl apply -f ingress-exposition/ingress-rules/

kubectl create namespace cloudflared
# créer le secret credentials AVANT cette étape (voir Secrets à recréer)
kubectl apply -f ingress-exposition/cloudflared-config.yaml
kubectl apply -f ingress-exposition/cloudflared-deployment.yaml
```

### 10. Mettre en place la sauvegarde etcd
```bash
chmod +x resilience/backup-etcd.sh
crontab -e   # ajouter une exécution quotidienne
```

### 11. Appliquer le dimensionnement horizontal/vertical
```bash
kubectl apply -f scaling/hpa-taskmanager.yaml
kubectl apply -f scaling/vpa-taskmanager.yaml
```

Installation du VPA (non fourni par défaut avec Kind) :
```bash
git clone https://github.com/kubernetes/autoscaler.git
cd autoscaler/vertical-pod-autoscaler
./hack/vpa-up.sh
```

### 12. Audits de sécurité (à exécuter ponctuellement)
```bash
# Résultats d'exemple inclus : security/kube-bench-kube-hunter/
python3 security/kube-bench-kube-hunter/generate_dashboard.py
```

## Secrets à recréer

Jamais versionnés ici — à recréer manuellement lors d'une reprise :

| Secret | Où | Comment |
|---|---|---|
| `credentials.json` (Cloudflare Tunnel) | avant l'étape 9 | `cloudflared tunnel login` puis `cloudflared tunnel create <nom>` |
| `grafana-smtp-secret` | namespace `monitoring` | `kubectl create secret generic grafana-smtp-secret --from-literal=user=... --from-literal=password=...` |
| Token GitHub (webhook Jenkins) | Gestionnaire d'identifiants Jenkins | Personal Access Token GitHub |
| Token SonarCloud | Gestionnaire d'identifiants Jenkins | Généré depuis SonarCloud |
| Token Docker Hub | Gestionnaire d'identifiants Jenkins | Depuis Docker Hub → Security |
| `kubeconfig` | local, jamais commité | Généré automatiquement par `kind create cluster` |
| `app-secret` (TaskManager) | namespace `devsecops` | `kubectl create secret generic app-secret --from-literal=SECRET_KEY=...` |
| `postgres-secret` | namespace `devsecops` | `kubectl create secret generic postgres-secret --from-literal=POSTGRES_PASSWORD=...` |
