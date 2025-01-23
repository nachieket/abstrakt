# ABSTRAKT

Abstrakt streamlines cloud operations by providing an intelligent abstraction layer that simplifies complex multi-cloud environments. It automates the deployment and management of Kubernetes clusters across AWS, Azure, and GCP, while seamlessly integrating CrowdStrike sensors. This orchestration significantly accelerates proof of value processes, enabling rapid security implementation and evaluation.

In upcoming releases, Abstrakt will expand its capabilities to facilitate enterprise-wide CrowdStrike sensor deployment. This enhancement will support large-scale rollouts across diverse environments, including multiple virtual machines and Kubernetes clusters, spanning numerous cloud accounts. This advancement will empower organizations to swiftly achieve comprehensive security coverage and maintain consistent protection across their entire cloud ecosystem.

### Usage

```
docker pull nachiketj/abstrakt:1.0.3

docker run -it nachiketj/abstrakt:1.0.3

Note: Check here for latest version of Abstrakt image - https://hub.docker.com/r/nachiketj/abstrakt/tags
```

### AWS

#### AWS EKS Managed Node Example

##### Create EKS Managed Node Cluster and Deploy Sensors via CrowdStrike Registry

```
abstrakt create aws eks-managed-node --cluster-name abstrakt-eks-managed-node --vpc-name abstrakt-eks-managed-node-vpc --region eu-west-2 --asset-tags "owner=Abstrakt,product=Falcon,accounting=dev,department=Security,business=IT" --install-falcon-sensor --sensor-tags EKS-MANAGED-NODE,ABSTRAKT,CRWD --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Create EKS Managed Node Cluster and Deploy Sensors via AWS ECR Registry

```
abstrakt create aws eks-managed-node --cluster-name abstrakt-eks-managed-node --vpc-name abstrakt-eks-managed-node-vpc --region eu-west-2 --asset-tags "owner=Abstrakt,product=Falcon,accounting=dev,department=Security,business=IT" --install-falcon-sensor --registry 123456789012.dkr.ecr.eu-west-2.amazonaws.com --install-falcon-sensor --sensor-tags EKS-MANAGED-NODE,ABSTRAKT,CRWD --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Install CrowdStrike Sensors via CrowdStrike Registry

```
abstrakt install crowdstrike --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --aws-cluster abstrakt-eks-managed-node --aws-region eu-west-2 --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Install CrowdStrike Sensors via AWS ECR Registry

```
abstrakt install crowdstrike --falcon-sensor --kac --iar --registry 123456789012.dkr.ecr.eu-west-2.amazonaws.com --detections-container --vulnerable-apps --generate-misconfigs --aws-cluster abstrakt-eks-managed-node --aws-region eu-west-2 --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Uninstall Sensors

```
abstrakt uninstall crowdstrike --aws-cluster abstrakt-eks-managed-node --aws-region eu-west-2 --falcon-sensor --kac --iar --detections-containers
```

##### Delete Cluster

```
abstrakt delete aws eks-fargate --cluster abstrakt-eks-managed-node --region eu-west-2
```

#### AWS EKS Fargate Example

##### Create EKS Managed Node Cluster and Deploy Sensors via CrowdStrike Registry

```
abstrakt create aws eks-fargate --cluster-name abstrakt-eks-fargate --vpc-name abstrakt-fargate-vpc --region eu-west-2 --asset-tags "owner=Abstrakt,product=Falcon,accounting=dev,department=Security,business=IT" --install-falcon-sensor --sensor-tags EKS-FARGATE,ABSTRAKT,CRWD --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Create EKS Managed Node Cluster and Deploy Sensors via AWS ECR Registry

```
abstrakt create aws eks-fargate --cluster-name abstrakt-eks-fargate --vpc-name abstrakt-fargate-vpc --region eu-west-2 --asset-tags "owner=Abstrakt,product=Falcon,accounting=dev,department=Security,business=IT" --registry 123456789012.dkr.ecr.eu-west-2.amazonaws.com --install-falcon-sensor --sensor-tags EKS-FARGATE,ABSTRAKT,CRWD --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Install CrowdStrike Sensors via CrowdStrike Registry

```
abstrakt install crowdstrike --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --aws-cluster abstrakt-eks-fargate --aws-region eu-west-2 --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Install CrowdStrike Sensors via AWS ECR Registry

```
abstrakt install crowdstrike --falcon-sensor --kac --iar --registry 123456789012.dkr.ecr.eu-west-2.amazonaws.com --detections-container --vulnerable-apps --generate-misconfigs --aws-cluster abstrakt-eks-fargate --aws-region eu-west-2 --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Uninstall Sensors

```
abstrakt uninstall crowdstrike --aws-cluster abstrakt-eks-fargate --aws-region eu-west-2 --falcon-sensor --kac --iar --detections-containers
```

##### Delete Cluster

```
abstrakt delete aws eks-fargate --cluster abstrakt-eks-fargate --region eu-west-2
```

### Azure

#### Azure AKS Example

##### Create Azure AKS Cluster and Deploy Sensors via CrowdStrike Registry

```
abstrakt create azure aks --cluster-name abstrakt-aks1 --resource-group abstrakt-group1 --location uksouth --asset-tags "owner=Abstrakt,product=Falcon,accounting=dev,department=Security,business=IT" --install-falcon-sensor --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Create Azure AKS Cluster and Deploy Sensors via Azure ACR Registry

```
abstrakt create azure aks --cluster-name abstrakt-aks1 --resource-group abstrakt-group1 --location uksouth --asset-tags "owner=Abstrakt,product=Falcon,accounting=dev,department=Security,business=IT" --registry abstrakt.azurecr.io --sp-name abstrakt --install-falcon-sensor --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --acr-resource-group NJ --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Install CrowdStrike Sensors via CrowdStrike Registry

```
abstrakt install crowdstrike --az-cluster abstrakt-aks1 --az-resource-group abstrakt-group1 --az-location uksouth --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Install CrowdStrike Sensors via Åzure ACR Registry

```
abstrakt install crowdstrike --az-cluster abstrakt-aks1 --az-resource-group abstrakt-group1 --az-location uksouth --az-acr-resource-group NJ --registry abstrakt.azurecr.io --az-sp-name abstrakt --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Uninstall Sensors

```
abstrakt uninstall crowdstrike --az-cluster abstrakt-aks1 --az-resource-group abstrakt-group1 --falcon-sensor --kpa --kac --iar --detections-containers
```

##### Delete Cluster

```
abstrakt delete azure aks --cluster abstrakt-aks1 --resource-group abstrakt-group1
```

### GCP

#### GKE Standard Example

##### Create GKE Standard Cluster and Deploy Sensors via CrowdStrike Registry

```
abstrakt create gcp gke-standard --cluster-name abstrakt-gke-standard --vpc-network abstrakt-network --location europe-west2 --project-id project-xyz --asset-tags "owner-Asbtrakt,product-falcon,accounting-dev,department-Security,business-IT" --install-falcon-sensor --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Create GKE Standard Cluster and Deploy Sensors via GCP Artifact Registry

```
abstrakt create gcp gke-standard --cluster-name abstrakt-gke-standard --vpc-network abstrakt-network --location europe-west2 --project-id project-xyz --asset-tags "owner-Asbtrakt,product-falcon,accounting-dev,department-Security,business-IT" --registry europe-west2-docker.pkg.dev --service-account abstrakt-svc --install-falcon-sensor --sensor-tags GKE-STANDARD,CRWD,ABSTRAKT --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Install CrowdStrike Sensors via CrowdStrike Registry

```
abstrakt install crowdstrike --gcp-cluster abstrakt-gke-standard --gcp-location europe-west2 --gcp-project-id project-xyz --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Install CrowdStrike Sensors via GCP Artifact Registry

```
abstrakt install crowdstrike --gcp-cluster abstrakt-gke-standard --gcp-location europe-west2 --gcp-project-id project-xyz --registry europe-west2-docker.pkg.dev --gcp-service-account abstrakt-svc --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Uninstall Sensors

```
abstrakt uninstall crowdstrike --gcp-cluster abstrakt-gke-standard --gcp-location europe-west2 --gcp-project-id project-xyz --falcon-sensor --kac --iar --detections-containers
```

##### Delete Cluster

```
abstrakt delete gcp gke-standard --cluster abstrakt-gke-standard --region europe-west2 --project-id project-xyz
```

#### GKE Autopilot Example

##### Create GKE Autopilot Cluster and Deploy Sensors via CrowdStrike Registry

```
abstrakt create gcp gke-autopilot --cluster-name abstrakt-gke-autopilot --vpc-network gke-autopilot-network --location europe-west2 --project-id project-xyz --install-falcon-sensor --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Install CrowdStrike Sensors via CrowdStrike Registry

```
abstrakt install crowdstrike --gcp-cluster abstrakt-gke-autopilot --gcp-location europe-west2 --gcp-project-id project-xyz --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117bREDACTED --falcon-client-secret xqKpyF07TIREDACTED
```

##### Uninstall Sensors

```
abstrakt uninstall crowdstrike --gcp-cluster abstrakt-gke-autopilot --gcp-location europe-west2 --gcp-project-id project-xyz --falcon-sensor --kac --iar --detections-containers
```

##### Delete Cluster

```
abstrakt delete gcp gke-standard --cluster abstrakt-gke-autopilot --region europe-west2 --project-id project-xyz
```
