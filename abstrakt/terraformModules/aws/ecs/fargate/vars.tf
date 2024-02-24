variable "region" {
  default = "eu-west-2"
}

variable "cluster_name" {
  default = "random-ecs-cluster"
}

variable "ecs_service_name" {
  default = "random-ecs-service"
}

variable "alb_name" {
  default = "random-ecs-alb"
}

variable "vpc_name" {
  default = "random-ecs"
}

variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

variable "common_tags" {
  default = {
    vendor = "CrowdStrike"
  }
}
