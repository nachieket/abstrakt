# ABSTRAKT

## Create Public Cloud Clusters with CrowdStrike Sensors

### AWS

#### AWS EKS Managed Node Example

##### CrowdStrike Repo

abstrakt create aws eks-managed-node --install-falcon-sensor --kernel-mode --falcon-sensor-tags CRWD,
EKS-MANAGED-NODE --install-kpa --install-kac --install-iar --install-detections-container --install-vulnerable-apps 
--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

##### AWS Repo

abstrakt create aws eks-managed-node --install-falcon-sensor --kernel-mode --falcon-image-repo 123456789012.dkr.ecr.
eu-west-2.amazonaws.com/ecr --falcon-sensor-tags CRWD,EKS-MANAGED-NODE --install-kpa --install-kac 
--install-iar --install-detections-container --install-vulnerable-apps --falcon-client-id 
3af74117 --falcon-client-secret vlTpn372s

#### AWS EKS Fargate Example

##### CrowdStrike Repo

abstrakt create aws eks-fargate --install-falcon-sensor --falcon-sensor-tags CRWD,EKS-FARGATE --install-kpa 
--install-kac --install-iar --install-detections-container --install-vulnerable-apps --falcon-client-id 
3af74117 --falcon-client-secret vlTpn372s

##### AWS Repo

abstrakt create aws eks-fargate --install-falcon-sensor --falcon-image-repo 123456789012.dkr.ecr.eu-west-2.amazonaws.
com/ecr --falcon-sensor-tags CRWD,EKS-FARGATE --install-kpa --install-kac --install-iar 
--install-detections-container --install-vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

### Azure

#### Azure AKS Example

##### CrowdStrike Repo

abstrakt create azure aks --install-falcon-sensor --ebpf-mode --falcon-sensor-tags CRWD,AKS --install-kpa 
--install-kac --install-iar --install-detections-container --install-vulnerable-apps --falcon-client-id 
3af74117 --falcon-client-secret vlTpn372s

### GCP

#### GCP Standard Example

##### CrowdStrike Repo

abstrakt create gcp gke-standard --install-falcon-sensor --falcon-sensor-tags CRWD,GKE-STANDARD --install-kpa 
--install-kac --install-iar --install-detections-container --install-vulnerable-apps --falcon-client-id 
3af74117 --falcon-client-secret vlTpn372s --gcp-project-id crwd-123456

#### GCP Autopilot Example

##### CrowdStrike Repo

abstrakt create gcp gke-autopilot --install-falcon-sensor --falcon-sensor-tags CRWD,GKE-AUTOPILOT --install-kpa 
--install-kac --install-iar --install-detections-container --install-vulnerable-apps --falcon-client-id 
3af74117 --falcon-client-secret vlTpn372s --gcp-project-id crwd-123456

## Install CrowdStrike Sensors

### AWS

#### AWS EKS Managed Node Example

##### CrowdStrike Repo

abstrakt install crowdstrike --falcon-sensor --kernel-mode --falcon-sensor-tags CRWD,EKS-MANAGED-NODE 
--aws-cluster-name random-eks-managed-node-cluster  --aws-region eu-west-2 --kpa --kac --iar --detections-container 
--vulnerable-apps --falcon-client-id  3af74117 --falcon-client-secret vlTpn372s

##### AWS Repo

abstrakt install crowdstrike --falcon-sensor --kernel-mode --falcon-image-repo 123456789012.dkr.ecr.eu-west-2.
amazonaws.com/ecr --falcon-sensor-tags CRWD,EKS-MANAGED-NODE --aws-cluster-name random-eks-managed-node-cluster 
--aws-region eu-west-2 --kpa --kac --iar --detections-container --vulnerable-apps --falcon-client-id 
3af74117 --falcon-client-secret vlTpn372s

#### AWS EKS Fargate Example

##### CrowdStrike Repo

abstrakt install crowdstrike --falcon-sensor --monitor-namespaces all --exclude-namespaces ns1,ns2 
--falcon-sensor-tags CRWD,EKS-MANAGED-NODE  --aws-cluster-name random-eks-managed-node-cluster 
--aws-region eu-west-2 --kpa --kac --iar --detections-container --vulnerable-apps --falcon-client-id 3af74117 
--falcon-client-secret vlTpn372s

##### AWS Repo

abstrakt install crowdstrike --falcon-sensor --monitor-namespaces all --exclude-namespaces ns1,ns2 
--falcon-image-repo 123456789012.dkr.ecr.eu-west-2.amazonaws.com/ecr --falcon-sensor-tags CRWD,EKS-MANAGED-NODE 
--aws-cluster-name random-eks-managed-node-cluster --aws-region eu-west-2 --kpa --kac --iar --detections-container 
--vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

### Azure

#### Azure AKS Example

abstrakt create azure aks --install-falcon-sensor --ebpf-mode --falcon-sensor-tags CRWD,AKS --install-kpa 
--install-kac --install-iar --install-detections-container --install-vulnerable-apps --falcon-client-id 
3af74117 --falcon-client-secret vlTpn372s

### GCP

#### GKE Standard Example

install crowdstrike --falcon-sensor --falcon-sensor-tags CRWD,GKE-STANDARD --gcp-cluster-name 
random-gke-standard-cluster --gcp-region europe-west2 --gcp-project-name crwd-234212 --kpa --kac --iar 
--detections-container --vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

#### GKE Autopilot Example

abstrakt install crowdstrike --falcon-sensor --falcon-sensor-tags CRWD,GKE-AUTOPILOT --gcp-cluster-name 
random-autopilot-cluster --gcp-region europe-west2 --gcp-project-name crwd-234212 --kpa --kac --iar 
--detections-container --vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s
