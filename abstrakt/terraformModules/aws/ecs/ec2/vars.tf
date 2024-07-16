variable "region" {
  default = "eu-west-2"
}

variable "vpc_name" {
  default = "random-vpc"
}

variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

variable "cluster_name" {
  default = "random-ecs-ec2-cluster"
}

variable "ecs_service_name" {
  default = "random-ecs-service"
}

variable "alb_name" {
  default = "random-alb"
}

variable "instance_type" {
  default = "t3.medium"
}

variable "iam_role_name" {
  default = "random-iam-role"
}

variable "autoscale_security_group_name" {
  default = "random-autoscale-security-group"
}

variable "instance_name_prefix" {
  default = "random-ecs"
}

variable "common_tags" {
  default = {
    vendor = "CrowdStrike"
  }
}

variable "random_string" {
  default = ""
}