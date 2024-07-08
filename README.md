# ABSTRAKT - A LAYER OF ABSTRACTION

## Create Public Cloud Clusters with CrowdStrike Sensors

### AWS

#### AWS EKS Managed Node Example

##### CrowdStrike Repo

abstrakt create aws eks-managed-node --install-falcon-sensor --kernel-mode --falcon-sensor-tags CRWD,NJ,
EKS-MANAGED-NODE --install-kpa --install-kac --install-iar --install-detections-container --install-vulnerable-apps 
--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

##### AWS Repo

abstrakt create aws eks-managed-node --install-falcon-sensor --kernel-mode --falcon-image-repo 123456789012.dkr.ecr.
eu-west-2.amazonaws.com/njecr --falcon-sensor-tags CRWD,NJ,EKS-MANAGED-NODE --install-kpa --install-kac 
--install-iar --install-detections-container --install-vulnerable-apps --falcon-client-id 
3af74117 --falcon-client-secret vlTpn372s

#### AWS EKS Fargate Example

##### CrowdStrike Repo

abstrakt create aws eks-fargate --install-falcon-sensor --falcon-sensor-tags CRWD,NJ,EKS-FARGATE --install-kpa 
--install-kac --install-iar --install-detections-container --install-vulnerable-apps --falcon-client-id 
3af74117 --falcon-client-secret vlTpn372s

##### AWS Repo

abstrakt create aws eks-fargate --install-falcon-sensor --falcon-image-repo 123456789012.dkr.ecr.eu-west-2.amazonaws.
com/njecr --falcon-sensor-tags CRWD,NJ,EKS-FARGATE --install-kpa --install-kac --install-iar 
--install-detections-container --install-vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

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

abstrakt create azure aks --install-falcon-sensor --ebpf-mode --falcon-sensor-tags CRWD,NJ,AKS --install-kpa 
--install-kac --install-iar --install-detections-container --install-vulnerable-apps --falcon-client-id 
3af74117 --falcon-client-secret vlTpn372s

### GCP

#### GKE Standard Example

install crowdstrike --falcon-sensor --falcon-sensor-tags CRWD,NJ,GKE-STANDARD --gcp-cluster-name 
random-gke-standard-cluster --gcp-region europe-west2 --gcp-project-name njcsa-369315 --kpa --kac --iar 
--detections-container --vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

#### GKE Autopilot Example

abstrakt install crowdstrike --falcon-sensor --falcon-sensor-tags CRWD,NJ,GKE-AUTOPILOT --gcp-cluster-name 
random-autopilot-cluster --gcp-region europe-west2 --gcp-project-name njcsa-369315 --kpa --kac --iar 
--detections-container --vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s
