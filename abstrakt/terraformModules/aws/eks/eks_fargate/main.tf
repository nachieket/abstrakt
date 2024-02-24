provider "aws" {
  region = var.region
}

data "aws_availability_zones" "available" {}

locals {
  azs  = slice(data.aws_availability_zones.available.names, 0, var.az_count)
}

module "eks" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name                   = var.cluster_name
  cluster_version                = var.cluster_version
  cluster_endpoint_public_access = true

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.intra_subnets

  # Fargate profiles use the cluster primary security group so these are not utilized
  create_cluster_security_group = false
  create_node_security_group    = false

  fargate_profile_defaults = {
    iam_role_additional_policies = {
      additional = aws_iam_policy.additional.arn
    }
  }

  fargate_profiles = merge(
    {
      default = {
        name = "default"
        selectors = [
          {
            namespace = "default"
          }
        ]
        subnet_ids = [module.vpc.private_subnets[1]]
        tags = var.common_tags
        timeouts = {
          create = "20m"
          delete = "20m"
        }
      },
      falcon-system = {
        name = "falcon-system"
        selectors = [
          {
            namespace = "falcon-system"
          }
        ]
        subnet_ids = [module.vpc.private_subnets[1]]
        tags = var.common_tags
        timeouts = {
          create = "20m"
          delete = "20m"
        }
      },
      falcon-kac = {
        name = "falcon-kac"
        selectors = [
          {
            namespace = "falcon-kac"
          }
        ]
        subnet_ids = [module.vpc.private_subnets[1]]
        tags = var.common_tags
        timeouts = {
          create = "20m"
          delete = "20m"
        }
      },
      ns1 = {
        name = "ns1"
        selectors = [
          {
            namespace = "ns1"
          }
        ]
        subnet_ids = [module.vpc.private_subnets[1]]
        tags = var.common_tags
        timeouts = {
          create = "20m"
          delete = "20m"
        }
      },
      ns2 = {
        name = "ns2"
        selectors = [
          {
            namespace = "ns2"
          }
        ]
        subnet_ids = [module.vpc.private_subnets[1]]
        tags = var.common_tags
        timeouts = {
          create = "20m"
          delete = "20m"
        }
      },
      falcon-falcon-kubernetes-protection = {
        name = "falcon-kubernetes-protection"
        selectors = [
          {
            namespace = "falcon-kubernetes-protection"
          }
        ]
        subnet_ids = [module.vpc.private_subnets[1]]
        tags = var.common_tags
        timeouts = {
          create = "20m"
          delete = "20m"
        }
      },
      crowdstrike-detections = {
        name = "crowdstrike-detections"
        selectors = [
          {
            namespace = "crowdstrike-detections"
          }
        ]
        subnet_ids = [module.vpc.private_subnets[1]]
        tags = var.common_tags
        timeouts = {
          create = "20m"
          delete = "20m"
        }
      }
    },
    { for i in range(3) :
      "kube-system-${element(split("-", local.azs[i]), 2)}" => {
        selectors = [
          { namespace = "kube-system" }
        ]
        # We want to create a profile per AZ for high availability
        subnet_ids = [element(module.vpc.private_subnets, i)]
      }
    }
  )

  tags = var.common_tags
}

resource "aws_eks_addon" "example" {
  cluster_name                = module.eks.cluster_name
  addon_name                  = "coredns"
  resolve_conflicts_on_create = "OVERWRITE"
#  resolve_conflicts_on_update = "PRESERVE"

  timeouts {
    create = "5m"  # 5 minutes timeout for creation
  }

  configuration_values = jsonencode({
    computeType = "Fargate"
    replicaCount = 2
    resources = {
      limits = {
        cpu    = "100m"
        memory = "150Mi"
      }
      requests = {
        cpu    = "100m"
        memory = "150Mi"
      }
    }
  })
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.4.0"

  name = var.vpc_name
  cidr = var.vpc_cidr

  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 4, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k + 48)]
  intra_subnets   = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k + 52)]

  enable_nat_gateway                  = var.enable_nat_gateway
  single_nat_gateway                  = var.single_nat_gateway
  enable_dns_hostnames                = var.enable_dns_hostnames
  enable_flow_log                     = var.enable_flow_log
  create_flow_log_cloudwatch_iam_role = var.create_flow_log_cloudwatch_iam_role
  create_flow_log_cloudwatch_log_group = var.create_flow_log_cloudwatch_log_group

  tags = var.common_tags
}

resource "aws_route" "default_intra_rt_route" {
  for_each = { for idx, rt_id in module.vpc.intra_route_table_ids : idx => rt_id }

  route_table_id         = each.value
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = module.vpc.natgw_ids[0]
}

resource "aws_iam_policy" "additional" {
  name = "${var.vpc_name}-iam"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}
