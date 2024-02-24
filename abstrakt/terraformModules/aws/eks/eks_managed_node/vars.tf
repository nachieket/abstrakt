variable "region" {
  type        = string
  description = "AWS region"
}

variable "cluster_name" {
  type        = string
  description = "EKS cluster name"
}

variable "vpc_name" {
  type        = string
  description = "VPC name"
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR block"
}

variable "subnet_count" {
  type        = number
  description = "Number of subnets to use"
}

variable "private_subnets" {
  type        = list(string)
  description = "List of private subnet CIDR blocks"
}

variable "public_subnets" {
  type        = list(string)
  description = "List of public subnet CIDR blocks"
}

variable "enable_nat_gateway" {
  type        = bool
  description = "Enable NAT gateway"
  default = "true"
}

variable "single_nat_gateway" {
  type        = bool
  description = "Use single NAT gateway"
  default = "true"
}

variable "enable_dns_hostnames" {
  type        = bool
  description = "Enable DNS hostnames"
  default = "true"
}

variable "cluster_version" {
  type        = string
  description = "EKS cluster version"
}

variable "cluster_endpoint_public_access" {
  type        = bool
  description = "Enable public access to the cluster endpoint"
  default = "true"
}

variable "ami_type" {
  type        = string
  description = "AMI type for managed node groups"
}

variable "eks_managed_node_groups" {
  type = map(object({
    name          = string
    instance_types = list(string)
    min_size      = number
    max_size      = number
    desired_size  = number
  }))
  description = "Configuration for managed node groups"
}

variable "common_tags" {
  description = "A map of common tags to apply to all resources"
  type        = map(string)
  default     = {}
}
