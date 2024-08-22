# ABSTRAKT

## Create Public Cloud Clusters with CrowdStrike Sensors

### AWS

#### AWS EKS Managed Node Example

##### Deploy Sensors via CrowdStrike Repo

```
abstrakt create aws eks-managed-node --install-falcon-sensor --kernel-mode --sensor-tags CRWD,ABSTRAKT,
EKS-MANAGED-NODE --install-kac --install-iar --install-kpa --install-detections-container --install-vulnerable-apps 
--generate-misconfigs --falcon-client-id 3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED
```

##### Deploy Sensors via AWS Repo

```
abstrakt create aws eks-managed-node --install-falcon-sensor --kernel-mode --image-registry 123456789012.dkr.ecr.
eu-west-2.amazonaws.com/ecr --sensor-tags CRWD,ABSTRAKT,EKS-MANAGED-NODE --install-kac --install-iar --install-kpa 
--install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 3af74117REDACTED 
--falcon-client-secret vlTpn372sREDACTED
```

#### AWS EKS Fargate Example

##### Deploy Sensors via CrowdStrike Repo

```
abstrakt create aws eks-fargate --install-falcon-sensor --sensor-tags CRWD,ABSTRAKT,EKS-FARGATE --install-kac 
--install-iar --install-kpa --install-detections-container --install-vulnerable-apps --generate-misconfigs 
--falcon-client-id 3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED
```

##### Deploy Sensors via AWS Repo

```
abstrakt create aws eks-fargate --install-falcon-sensor --image-registry 123456789012.dkr.ecr.eu-west-2.amazonaws.
com/ecr --sensor-tags CRWD,ABSTRAKT,EKS-FARGATE --install-kac --install-iar --install-kpa 
--install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 
3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED
```

### Azure

#### Azure AKS Example

##### Deploy Sensors via CrowdStrike Repo

```
abstrakt create azure aks --install-falcon-sensor --ebpf-mode --sensor-tags CRWD,NJ,AKS --install-kpa --install-kac 
--install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs --falcon-client-id 
3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED
```

##### Deploy Sensors via Azure Repo

```
abstrakt create azure aks --install-falcon-sensor --ebpf-mode --image-registry abstrakt.azurecr.io/crowdstrike 
--sensor-tags CRWD,NJ,AKS --install-kpa --install-kac --install-iar --install-detections-container 
--install-vulnerable-apps --generate-misconfigs --acr-resource-group abstrakt --service-principal-name abstrakt 
--acr-subscription-id 11111111-0000-0000-0000-111111111111 --falcon-client-id 3af74117REDACTED 
--falcon-client-secret vlTpn372sREDACTED
```

### GCP

#### GKE Standard Example

##### Deploy Sensors via CrowdStrike Repo

```
abstrakt create gcp gke-standard --install-falcon-sensor --sensor-tags CRWD,NJ,GKE-STANDARD --install-kpa 
--install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs 
--falcon-client-id 3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED --gcp-project-id abstrakt-123456
```

#### GKE Autopilot Example

##### Deploy Sensors via CrowdStrike Repo

```
abstrakt create gcp gke-autopilot --install-falcon-sensor --sensor-tags CRWD,NJ,GKE-AUTOPILOT --install-kpa 
--install-kac --install-iar --install-detections-container --install-vulnerable-apps --generate-misconfigs 
--falcon-client-id 3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED --gcp-project-id abstrakt-123456
```

## Install CrowdStrike Sensors

### AWS

#### AWS EKS Managed Node Example

#### Deploy via CrowdStrike Registry

```
abstrakt install crowdstrike --falcon-sensor --kernel-mode --sensor-tags CRWD,ABSTRAKT,EKS-MANAGED-NODE 
--aws-cluster crowdstrike-eks-managed-node --aws-region eu-west-2 --kpa --kac --iar --detections-container 
--generate-misconfigs --vulnerable-apps --falcon-client-id 3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED
```

#### Deploy via AWS Registry

```
abstrakt install crowdstrike --falcon-sensor --kernel-mode --image-registry 123456789012.dkr.ecr.eu-west-2.
amazonaws.com/ecr --sensor-tags CRWD,ABSTRAKT,EKS-MANAGED-NODE --aws-cluster crowdstrike-eks-managed-node 
--aws-region eu-west-2 --kpa --kac --iar --detections-container --generate-misconfigs --vulnerable-apps 
--falcon-client-id 3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED
```

#### AWS EKS Fargate Example

#### Deploy via CrowdStrike Registry

```
abstrakt install crowdstrike --falcon-sensor --sensor-tags CRWD,ABSTRAKT,EKS-FARGATE --kpa --kac --iar 
--detections-container --generate-misconfigs --vulnerable-apps --aws-cluster crowdstrike-eks-fargate --aws-region 
eu-west-2 --falcon-client-id  3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED
```

#### Deploy via AWS Registry

```
abstrakt install crowdstrike --falcon-sensor --image-registry 123456789012.dkr.ecr.eu-west-2.amazonaws.com/ecr 
--sensor-tags CRWD,ABSTRAKT,EKS-FARGATE --kpa --kac --iar --detections-container --generate-misconfigs 
--vulnerable-apps --aws-cluster crowdstrike-eks-fargate --aws-region eu-west-2 --falcon-client-id  3af74117REDACTED 
--falcon-client-secret vlTpn372sREDACTED
```

### Azure

#### Azure AKS Example

#### Deploy via CrowdStrike Registry

```
abstrakt install crowdstrike --falcon-sensor --sensor-tags CRWD,NJ,AKS --kpa --kac --iar --detections-container 
--vulnerable-apps --generate-misconfigs --az-cluster abstrakt-aks --az-resource-group abstrakt 
--acr-resource-group xyz --service-principal-name abstrakt --acr-subscription-id 
11111111-0000-0000-0000-111111111111 --falcon-client-id 3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED
```

#### Deploy via Azure Registry

```
abstrakt install crowdstrike --falcon-sensor --image-registry abstrakt.azurecr.io/crowdstrike --sensor-tags CRWD,NJ,
AKS --kpa --kac --iar --detections-container --vulnerable-apps --generate-misconfigs --az-cluster abstrakt-aks 
--az-resource-group abstrakt --acr-resource-group xyz --service-principal-name abstrakt  --acr-subscription-id 
11111111-0000-0000-0000-111111111111 --falcon-client-id 3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED
```

### GCP

#### GKE Standard Example

#### Deploy via CrowdStrike Registry

```
abstrakt install crowdstrike --falcon-sensor --kpa --kac --iar --detections-container --vulnerable-apps 
--generate-misconfigs --gcp-cluster crowdstrike-gke-standard --gcp-region europe-west2 --gcp-project-id abstrakt-123456 
--falcon-client-id 3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED
```

#### GKE Autopilot Example

#### Deploy via CrowdStrike Registry

```
abstrakt install crowdstrike --falcon-sensor --kpa --kac --iar --detections-container --vulnerable-apps 
--generate-misconfigs --gcp-cluster crowdstrike-autopilot --gcp-region europe-west2 --gcp-project-id abstrakt-123456 
--falcon-client-id 3af74117REDACTED --falcon-client-secret vlTpn372sREDACTED
```
