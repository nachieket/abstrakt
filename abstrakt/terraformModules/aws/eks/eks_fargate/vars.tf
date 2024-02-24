variable "region" {
  description = "The AWS region to deploy the resources."
}

variable "az_count" {
  description = "The number of availability zones to use."
}

variable "cluster_name" {
  type        = string
  description = "EKS cluster name"
}

variable "vpc_name" {
  type        = string
  description = "VPC name"
}

variable "cluster_version" {
  description = "The version of the EKS cluster."
}

variable "cluster_endpoint_public_access" {
  description = "Whether the EKS cluster should be accessible publicly."
  default = "true"
}

variable "create_cluster_security_group" {
  description = "Whether to create a cluster security group for EKS."
  default = "true"
}

variable "create_node_security_group" {
  description = "Whether to create a node security group for EKS."
  default = "true"
}

variable "common_tags" {
  description = "Tags to apply to resources created by the Terraform module."
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC."
}

variable "enable_nat_gateway" {
  description = "Whether to enable a NAT gateway for the VPC."
  default = "true"
}

variable "single_nat_gateway" {
  description = "Whether to create a single NAT gateway for the VPC."
  default = "true"
}

variable "enable_dns_hostnames" {
  description = "Whether to enable DNS hostnames for the VPC."
  default = "true"
}

variable "enable_flow_log" {
  description = "Whether to enable VPC flow logs."
  default = "true"
}

variable "create_flow_log_cloudwatch_iam_role" {
  description = "Whether to create an IAM role for CloudWatch VPC flow logs."
  default = "true"
}

variable "create_flow_log_cloudwatch_log_group" {
  description = "Whether to create a CloudWatch log group for VPC flow logs."
  default = "true"
}
