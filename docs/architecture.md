# Architecture de la plateforme DevSecOps

Ce document résume l'architecture technique de la plateforme. Pour le détail
complet (contexte, étude comparative, résultats de validation), voir le
[rapport de stage complet](https://fr.overleaf.com/read/rhdvqnvhjpkj#cba1d4).

## Vue d'ensemble

La plateforme s'organise autour d'un cluster Kubernetes unique, hébergeant
l'ensemble des composants à l'exception des services externalisés
(GitHub, SonarCloud, Docker Hub). Elle est structurée en quatre domaines
fonctionnels, isolés par des espaces de noms distincts.

```mermaid
flowchart TB
    subgraph Externe["Services externalisés"]
        GH[GitHub]
        SC[SonarCloud]
        DH[Docker Hub]
    end

    subgraph Cluster["Cluster Kubernetes"]
        subgraph Livraison["Domaine de livraison"]
            Jenkins[Jenkins]
        end
        subgraph Securite["Domaine de sécurité"]
            Falco[Falco]
            Audit[Outils d'audit]
        end
        subgraph Applicatif["Domaine applicatif"]
            App[TaskManager]
            DB[(PostgreSQL)]
        end
        subgraph Observabilite["Domaine d'observabilité"]
            Prom[Prometheus]
            Loki[Loki]
            Graf[Grafana]
        end
    end

    GH --> Jenkins
    DH --> Jenkins
    SC --> Jenkins
    Jenkins -->|deploiement| App
    Applicatif -.->|metriques/logs| Observabilite
    Securite -.->|evenements| Observabilite
```

**Mapping avec le repo :**

| Domaine | Dossier |
|---|---|
| Livraison | `ci-cd/` |
| Securite | `security/` |
| Applicatif | `k8s/taskmanager/` |
| Observabilite | `observability/` |

## Architecture de securite — defense en profondeur

Cinq niveaux de controle complementaires couvrent le cycle de vie logiciel,
du code source jusqu'a l'execution en production.

```mermaid
flowchart LR
    A["1. Code source
    SAST + secrets"] --> B["2. Artefacts produits
    Images et IaC"]
    B --> C["3. Admission cluster
    Pod Security"]
    C --> D["4. Execution cluster
    RBAC"]
    D --> E["5. Production
    Runtime + audit"]
```

| Niveau | Outils | Dossier |
|---|---|---|
| Code source | Gitleaks, SonarCloud | `ci-cd/` |
| Artefacts | Checkov, Trivy | `ci-cd/`, `security/checkov/` |
| Admission cluster | Pod Security Standards | `k8s/pod-security/` |
| Execution cluster | RBAC | `k8s/rbac/` |
| Production | Falco, Kube-bench, Kube-hunter | `security/falco/`, `security/kube-bench-kube-hunter/` |

## Flux CI/CD

```mermaid
flowchart LR
    Push[Push GitHub] --> WH[Webhook]
    WH --> GL[Gitleaks]
    GL --> CK[Checkov]
    CK --> Tests[Tests unitaires]
    Tests --> SC[SonarCloud]
    SC --> Kaniko[Build Kaniko]
    Kaniko --> Trivy[Trivy]
    Trivy --> Deploy[Deploiement K8s]
```

Chaque etape est bloquante : un seuil de securite depasse interrompt le
pipeline. Le pipeline s'execute via des agents Jenkins ephemeres (pods crees
a la demande), defini dans `ci-cd/jenkins-deployment.yaml`. Le `Jenkinsfile`
lui-meme est versionne dans le
[repo applicatif](https://github.com/RiahiAmani/flask-postgres-docker-compose)
(Pipeline as Code).

## Architecture d'observabilite

```mermaid
flowchart TB
    subgraph Metriques["Metriques"]
        NE[Node Exporter] --> Prom[Prometheus]
        KSM[Kube-State-Metrics] --> Prom
        Prom --> AM[Alertmanager]
    end
    subgraph Logs["Journaux et securite"]
        PT[Promtail] --> Loki[Loki]
        Falco[Falco] --> Loki
    end
    Prom --> Grafana[Grafana]
    Loki --> Grafana
```

Configuration : `observability/prometheus/`, `observability/loki-promtail/`,
`observability/grafana/`.

## Modele d'exposition des services

```mermaid
flowchart LR
    Client[Client externe] --> CF["Cloudflare
    resolution/chiffrement"]
    CF --> Tunnel["Cloudflare Tunnel
    connexion sortante"]
    Tunnel --> Ingress["NGINX Ingress
    routage par domaine"]
    Ingress --> Jenkins2[jenkins.riahi.dpdns.org]
    Ingress --> Grafana2[grafana.riahi.dpdns.org]
    Ingress --> App2[taskmanager.riahi.dpdns.org]
    Ingress --> Dash[dashboard.riahi.dpdns.org]
```

Aucun port entrant n'est ouvert sur le reseau prive : le tunnel etablit une
connexion sortante vers l'infrastructure Cloudflare. Configuration :
`ingress-exposition/`.

## Resilience et scaling

- Sauvegarde : script `resilience/backup-etcd.sh`, execution quotidienne
  via Cron, retention 7 jours, snapshot copie vers la machine hote.
- Scaling horizontal : `scaling/hpa-taskmanager.yaml` (Horizontal Pod
  Autoscaler, seuil CPU).
- Scaling vertical : `scaling/taskmanager-app-vpa.yaml` et
  `taskmanager-postgres-vpa.yaml` (Vertical Pod Autoscaler, mode
  recommandation uniquement).

## Pour aller plus loin

Voir le [guide de reproduction complet](../README.md) pour deployer cette
architecture depuis zero, et le
[rapport de stage](https://fr.overleaf.com/read/rhdvqnvhjpkj#cba1d4) pour
l'etude comparative des technologies et les resultats detailles de
validation.
