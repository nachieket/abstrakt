Install CrowdStrike Sensors

Example Usages:
abstrakt install --falcon-sensor --kernel-mode --kpa --kac --iar --detections-container --vulnerable-apps 
--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s
abstrakt install --falcon-sensor --kernel-mode --proxy-server 10.10.10.11 --proxy-port 8080 --falcon-sensor-tags 
tag1,tag2 --kpa --kac --iar --detections-container --vulnerable-apps --falcon-client-id 3af74117 
--falcon-client-secret vlTpn372s

Examples with Monitored/Excluded Namespaces for EKS Fargate:
abstrakt install --falcon-sensor --monitor-namespaces ns1,ns2,ns4,ns5 --kpa --kac --iar --detections-container 
--vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s
abstrakt install --falcon-sensor --monitor-namespaces all --exclude-namespaces ns1,ns2 --proxy-server 10.10.10.11 
--proxy-port 8080 --falcon-sensor-tags tag1,tag2 --kpa --kac --iar --detections-container --vulnerable-apps 
--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

Examples with Falcon Image Tag:
abstrakt install --falcon-sensor --kernel-mode --falcon-image-tag 7.10.0-16303-1.falcon-linux.x86_64.Release.US-1
--kpa --kac --iar --detections-container --vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret 
vlTpn372s
abstrakt install --falcon-sensor --kernel-mode --falcon-image-tag 7.10.0-16303-1.falcon-linux.x86_64.Release.US-1 
--proxy-server 10.10.10.11 --proxy-port 8080 --falcon-sensor-tags tag1,tag2 --kpa --kac --iar --detections-container 
--vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

###########
### AWS ###
###########

AWS Example - All CrowdStrike Sensors with Detections Container and Vulnerable Apps:
abstrakt install crowdstrike --falcon-sensor --kernel-mode --kpa --kac --iar --detections-container 
--vulnerable-apps --cloud-provider aws --cluster-type eks-managed-node --cluster-name random_eks_cluster 
--cloud-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

AWS Example - Falcon Sensor Installation:
abstrakt install crowdstrike --falcon-sensor --kernel-mode --cloud-provider aws --cluster-type eks-managed-node 
--cluster-name random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret 
vlTpn372s

AWS Example - Kubernetes Protection Agent Installation:
abstrakt install crowdstrike --kpa --cloud-provider aws --cluster-type eks-managed-node --cluster-name 
random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

AWS Example - Kubernetes Admission Controller Installation:
abstrakt install crowdstrike --kac --cloud-provider aws --cluster-type eks-managed-node --cluster-name 
random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

AWS Example - Image Assessment at Runtime Installation:
abstrakt install crowdstrike --iar --cloud-provider aws --cluster-type eks-managed-node --cluster-name 
random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s

AWS Example - Detections Container Installation:
abstrakt install crowdstrike --detections-container --cloud-provider aws --cluster-type eks-managed-node 
--cluster-name random_eks_cluster --cloud-region eu-west-2

AWS Example - Vulnerable Apps Installation:
abstrakt install crowdstrike --vulnerable-apps ---cloud-provider aws --cluster-type eks-managed-node --cluster-name 
random_eks_cluster --cloud-region eu-west-2

#############
### Azure ###
#############

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

###########
### GCP ###
###########

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
