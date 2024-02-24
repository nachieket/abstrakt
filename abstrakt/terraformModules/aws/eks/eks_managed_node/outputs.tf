# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "region" {
  description = "AWS region"
  value       = var.region
}

output "vpc_id" {
  description = "The VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnets" {
  description = "The private subnets"
  value       = module.vpc.private_subnets
}

output "public_subnets" {
  description = "The public subnets"
  value       = module.vpc.public_subnets
}

output "nat_gateways" {
  description = "The NAT gateways"
  value       = module.vpc.natgw_ids
}

output "eks_cluster_id" {
  description = "The EKS cluster ID"
  value       = module.eks.cluster_id
}

output "eks_cluster_name" {
  description = "The EKS cluster name"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "The EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ids attached to the cluster control plane"
  value       = module.eks.cluster_security_group_id
}

output "eks_cluster_certificate_authority_data" {
  description = "The EKS cluster certificate authority data"
  value       = module.eks.cluster_certificate_authority_data
}

output "eks_oidc_provider" {
  description = "The EKS cluster OIDC provider"
  value       = module.eks.oidc_provider
}

output "eks_managed_node_groups" {
  description = "The EKS managed node groups"
  value       = module.eks.eks_managed_node_groups
}

output "irsa_ebs_csi_iam_role_arn" {
  description = "The IAM role ARN for the EBS CSI driver"
  value       = module.irsa-ebs-csi.iam_role_arn
}

output "ebs_csi_addon_name" {
  description = "The EBS CSI addon name"
  value       = aws_eks_addon.ebs-csi.addon_name
}

output "ebs_csi_addon_version" {
  description = "The EBS CSI addon version"
  value       = aws_eks_addon.ebs-csi.addon_version
}

output "ebs_csi_addon_service_account_role_arn" {
  description = "The EBS CSI addon service account role ARN"
  value       = aws_eks_addon.ebs-csi.service_account_role_arn
}
