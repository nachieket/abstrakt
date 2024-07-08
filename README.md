# Install CrowdStrike Sensors

## AWS

### AWS EKS Managed Node Example

#### CrowdStrike Repo

abstrakt install crowdstrike --falcon-sensor --kernel-mode --falcon-sensor-tags CRWD,EKS-MANAGED-NODE 
--aws-cluster-name random-eks-managed-node-cluster  --aws-region eu-west-2 --kpa --kac --iar --detections-container 
--vulnerable-apps --falcon-client-id  3af74117 --falcon-client-secret vlTpn372s

#### AWS Repo

abstrakt install crowdstrike --falcon-sensor --kernel-mode --falcon-image-repo 123456789012.dkr.ecr.eu-west-2.
amazonaws.com/ecr --falcon-sensor-tags CRWD,EKS-MANAGED-NODE --aws-cluster-name random-eks-managed-node-cluster 
--aws-region eu-west-2 --kpa --kac --iar --detections-container --vulnerable-apps --falcon-client-id 
3af74117 --falcon-client-secret vlTpn372s

### AWS EKS Fargate Example

#### CrowdStrike Repo

abstrakt install crowdstrike --falcon-sensor --monitor-namespaces all --exclude-namespaces ns1,ns2 
--falcon-sensor-tags CRWD,EKS-MANAGED-NODE  --aws-cluster-name random-eks-managed-node-cluster 
--aws-region eu-west-2 --kpa --kac --iar --detections-container --vulnerable-apps --falcon-client-id 3af74117 
--falcon-client-secret vlTpn372s

#### AWS Repo

abstrakt install crowdstrike --falcon-sensor --monitor-namespaces all --exclude-namespaces ns1,ns2 
--falcon-image-repo 123456789012.dkr.ecr.eu-west-2.amazonaws.com/ecr --falcon-sensor-tags CRWD,EKS-MANAGED-NODE 
--aws-cluster-name random-eks-managed-node-cluster --aws-region eu-west-2 --kpa --kac --iar --detections-container 
--vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

## Azure

Azure Example - All CrowdStrike Sensors with Detections Container and Vulnerable Apps:
abstrakt install crowdstrike --falcon-sensor --kernel-mode --kpa --kac --iar --detections-container 
--vulnerable-apps --cloud-provider azure --cluster-type aks --cluster-name random_aks_cluster 
--azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

Azure Example - Falcon Sensor Installation:
abstrakt install crowdstrike --falcon-sensor --kernel-mode --cloud-provider azure --cluster-type aks --cluster-name 
random_aks_cluster --azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret 
vlTpn372s

Azure Example - Kubernetes Protection Agent Installation:
abstrakt install crowdstrike --kpa --cloud-provider azure --cluster-type aks --cluster-name random_aks_cluster 
--azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

Azure Example - Kubernetes Admission Controller Installation:
abstrakt install crowdstrike --kac --cloud-provider azure --cluster-type aks --cluster-name random_aks_cluster 
--azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

Azure Example - Image Assessment at Runtime Installation:
abstrakt install crowdstrike --iar --cloud-provider azure --cluster-type aks --cluster-name random_aks_cluster 
--azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

Azure Example - Detections Container Installation:
abstrakt install crowdstrike --detections-container --cloud-provider azure --cluster-type aks --cluster-name 
random_aks_cluster --azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret 
vlTpn372s

Azure Example - Vulnerable Apps Installation:
abstrakt install crowdstrike --vulnerable-apps --cloud-provider azure --cluster-type aks --cluster-name 
random_aks_cluster --azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret 
vlTpn372s

## GCP

GCP Example - All CrowdStrike Sensors with Detections Container and Vulnerable Apps:
abstrakt install crowdstrike --falcon-sensor --kpa --kac --iar --detections-container 
--vulnerable-apps --cloud-provider gcp --cluster-type gke-standard --cluster-name random_gke_cluster 
--cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

GCP Example - Falcon Sensor Installation:
abstrakt install crowdstrike --falcon-sensor --cloud-provider gcp --cluster-type gke-standard 
--cluster-name random_gke_cluster --cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 
--falcon-client-secret vlTpn372s

GCP Example - Kubernetes Protection Agent Installation:
abstrakt install crowdstrike --kpa --cloud-provider gcp --cluster-type gke-standard --cluster-name random_gke_cluster 
--cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

GCP Example - Kubernetes Admission Controller Installation:
abstrakt install crowdstrike --kac --cloud-provider gcp --cluster-type gke-standard --cluster-name random_gke_cluster 
--cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

GCP Example - Image Assessment at Runtime Installation:
abstrakt install crowdstrike --iar --cloud-provider gcp --cluster-type gke-standard --cluster-name random_gke_cluster 
--cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

GCP Example - Detections Container Installation:
abstrakt install crowdstrike --detections-container --cloud-provider gcp --cluster-type gke-standard --cluster-name 
random_gke_cluster --cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 
--falcon-client-secret vlTpn372s

GCP Example - Vulnerable Apps Installation:
abstrakt install crowdstrike --vulnerable-apps --cloud-provider gcp --cluster-type gke-standard --cluster-name 
random_gke_cluster --cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 
--falcon-client-secret vlTpn372s
