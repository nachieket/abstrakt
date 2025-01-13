# ABSTRAKT

## Create Public Cloud Clusters with CrowdStrike Sensors

### AWS

#### AWS EKS Managed Node Example

##### Create EKS Managed Node Cluster and Deploy Sensors via CrowdStrike Registry

```
abstrakt create aws eks-managed-node --cluster-name abstrakt-eks-managed-node --vpc-name abstrakt-eks-managed-node-vpc --region eu-west-2 --asset-tags "cstag-owner=njoshi02,cstag-product=Falcon,cstag-accounting=dev,cstag-department=Sales - 310000,cstag-business=Sales" --install-falcon-sensor --sensor-tags EKS-MANAGED-NODE,ABSTRAKT,CRWD --install-kac --install-iar --install-kpa --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Create EKS Managed Node Cluster and Deploy Sensors via AWS ECR Registry

```
abstrakt create aws eks-managed-node --cluster-name abstrakt-eks-managed-node --vpc-name abstrakt-eks-managed-node-vpc --region eu-west-2 --asset-tags "cstag-owner=njoshi02,cstag-product=Falcon,cstag-accounting=dev,cstag-department=Sales - 310000,cstag-business=Sales" --install-falcon-sensor --registry 517716713836.dkr.ecr.eu-west-2.amazonaws.com --install-falcon-sensor --sensor-tags EKS-MANAGED-NODE,ABSTRAKT,CRWD --install-kac --install-iar --install-kpa --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Install CrowdStrike Sensors via CrowdStrike Registry

```
abstrakt install crowdstrike --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --aws-cluster abstrakt-eks-managed-node --aws-region eu-west-2 --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Install CrowdStrike Sensors via AWS ECR Registry

```
abstrakt install crowdstrike --falcon-sensor --kac --iar --registry 517716713836.dkr.ecr.eu-west-2.amazonaws.com --detections-container --vulnerable-apps --generate-misconfigs --aws-cluster abstrakt-eks-managed-node --aws-region eu-west-2 --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Uninstall Sensors

```
abstrakt uninstall crowdstrike --aws-cluster abstrakt-eks-managed-node --aws-region eu-west-2 --falcon-sensor --kac --iar --detections-containers
```

#### AWS EKS Fargate Example

##### Create EKS Managed Node Cluster and Deploy Sensors via CrowdStrike Registry

```
abstrakt create aws eks-fargate --cluster-name abstrakt-eks-fargate --vpc-name abstrakt-fargate-vpc --region eu-west-2 --asset-tags "cstag-owner=njoshi02,cstag-product=Falcon,cstag-accounting=dev,cstag-department=Sales - 310000,cstag-business=Sales" --install-falcon-sensor --sensor-tags EKS-FARGATE,ABSTRAKT,CRWD --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Create EKS Managed Node Cluster and Deploy Sensors via AWS ECR Registry

```
abstrakt create aws eks-fargate --cluster-name abstrakt-eks-fargate --vpc-name abstrakt-fargate-vpc --region eu-west-2 --asset-tags "cstag-owner=njoshi02,cstag-product=Falcon,cstag-accounting=dev,cstag-department=Sales - 310000,cstag-business=Sales" --registry 517716713836.dkr.ecr.eu-west-2.amazonaws.com --install-falcon-sensor --sensor-tags EKS-FARGATE,ABSTRAKT,CRWD --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Install CrowdStrike Sensors via CrowdStrike Registry

```
abstrakt install crowdstrike --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --aws-cluster abstrakt-eks-fargate --aws-region eu-west-2 --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Install CrowdStrike Sensors via AWS ECR Registry

```
abstrakt install crowdstrike --falcon-sensor --kac --iar --registry 517716713836.dkr.ecr.eu-west-2.amazonaws.com --detections-container --vulnerable-apps --generate-misconfigs --aws-cluster abstrakt-eks-fargate --aws-region eu-west-2 --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Uninstall Sensors

```
abstrakt uninstall crowdstrike --aws-cluster abstrakt-eks-fargate --aws-region eu-west-2 --falcon-sensor --kac --iar --detections-containers
```

### Azure

#### Azure AKS Example

##### Create Azure AKS Cluster and Deploy Sensors via CrowdStrike Registry

```
abstrakt create azure aks --cluster-name abstrakt-aks1 --resource-group abstrakt-group1 --location uksouth --asset-tags "cstag-owner=njoshi02,cstag-product=Falcon,cstag-accounting=dev,cstag-department=Sales - 310000,cstag-business=Sales" --install-falcon-sensor --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Create Azure AKS Cluster and Deploy Sensors via Azure ACR Registry

```
abstrakt create azure aks --cluster-name abstrakt-aks1 --resource-group abstrakt-group1 --location uksouth --asset-tags "cstag-owner=njoshi02,cstag-product=Falcon,cstag-accounting=dev,cstag-department=Sales - 310000,cstag-business=Sales" --registry abstrakt.azurecr.io --sp-name abstrakt --install-falcon-sensor --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --acr-resource-group NJ --acr-sub-id 5a84cb53-b383-44db-bd58-c65ca3dfcb8c --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Install CrowdStrike Sensors via CrowdStrike Registry

```
abstrakt install crowdstrike --az-cluster abstrakt-aks1 --az-resource-group abstrakt-group1 --az-location uksouth --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Install CrowdStrike Sensors via Åzure ACR Registry

```
abstrakt install crowdstrike --az-cluster abstrakt-aks1 --az-resource-group abstrakt-group1 --az-location uksouth --az-acr-resource-group NJ --az-acr-sub-id 5a84cb53-b383-44db-bd58-c65ca3dfcb8c --registry abstrakt.azurecr.io --az-sp-name abstrakt --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Uninstall Sensors

```
abstrakt uninstall crowdstrike --az-cluster abstrakt-aks1 --az-resource-group abstrakt-group1 --falcon-sensor --kpa --kac --iar --detections-containers
```

### GCP

#### GKE Standard Example

##### Create GKE Standard Cluster and Deploy Sensors via CrowdStrike Registry

```
abstrakt create gcp gke-standard --cluster-name abstrakt-gke-standard --vpc-network abstrakt-network --location europe-west2 --project-id njcsa-369315 --asset-tags "cstag-owner-njoshi02,cstag-product-falcon,cstag-accounting-dev,cstag-department-sales-310000,cstag-business-sales" --install-falcon-sensor --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Create GKE Standard Cluster and Deploy Sensors via GCP Artifact Registry

```
abstrakt create gcp gke-standard --cluster-name abstrakt-gke-standard --vpc-network abstrakt-network --location europe-west2 --project-id njcsa-369315 --asset-tags "cstag-owner-njoshi02,cstag-product-falcon,cstag-accounting-dev,cstag-department-sales-310000,cstag-business-sales" --registry europe-west2-docker.pkg.dev --service-account abstrakt-svc --install-falcon-sensor --sensor-tags GKE-STANDARD,CRWD,ABSTRAKT --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Install CrowdStrike Sensors via CrowdStrike Registry

```
abstrakt install crowdstrike --gcp-cluster abstrakt-gke-standard --gcp-location europe-west2 --gcp-project-id njcsa-369315 --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Install CrowdStrike Sensors via GCP Artifact Registry

```
abstrakt install crowdstrike --gcp-cluster abstrakt-gke-standard --gcp-location europe-west2 --gcp-project-id njcsa-369315 --registry europe-west2-docker.pkg.dev --gcp-service-account abstrakt-svc --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Uninstall Sensors

```
abstrakt uninstall crowdstrike --gcp-cluster abstrakt-gke-standard --gcp-location europe-west2 --gcp-project-id njcsa-369315 --falcon-sensor --kac --iar --detections-containers
```

#### GKE Autopilot Example

##### Create GKE Autopilot Cluster and Deploy Sensors via CrowdStrike Registry

```
abstrakt create gcp gke-autopilot --cluster-name abstrakt-gke-autopilot --vpc-network gke-autopilot-network --location europe-west2 --project-id njcsa-369315 --install-falcon-sensor --install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Install CrowdStrike Sensors via CrowdStrike Registry

```
abstrakt install crowdstrike --gcp-cluster abstrakt-gke-autopilot --gcp-location europe-west2 --gcp-project-id njcsa-369315 --falcon-sensor --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117b84f4e04b29baf6840243fbc --falcon-client-secret xqKpyF07TIDGz1YMw2JlP4ZOmbuC98VHQ3Ek56Xt
```

##### Uninstall Sensors

```
abstrakt uninstall crowdstrike --gcp-cluster abstrakt-gke-autopilot --gcp-location europe-west2 --gcp-project-id njcsa-369315 --falcon-sensor --kac --iar --detections-containers
```
