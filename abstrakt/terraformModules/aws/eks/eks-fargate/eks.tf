resource "aws_iam_role" "eks-cluster" {
  name = "eks-fargate-${var.cluster_name}"

  assume_role_policy = <<POLICY
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "eks.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }
    POLICY
}

resource "aws_iam_role_policy_attachment" "amazon-eks-cluster-policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks-cluster.name
}

resource "aws_eks_cluster" "cluster" {
  name     = var.cluster_name
  version  = var.cluster_version
  role_arn = aws_iam_role.eks-cluster.arn

  vpc_config {

    endpoint_private_access = false
    endpoint_public_access  = true
    public_access_cidrs     = [var.public_access_cidrs]

    subnet_ids = [
      aws_subnet.private-subnet-a.id,
      aws_subnet.private-subnet-b.id,
      aws_subnet.public-subnet-a.id,
      aws_subnet.public-subnet-b.id
    ]
  }

  depends_on = [aws_iam_role_policy_attachment.amazon-eks-cluster-policy]
}

resource "aws_eks_addon" "example" {
  cluster_name                = var.cluster_name
  addon_name                  = "coredns"
#  resolve_conflicts_on_create = "OVERWRITE"
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

  depends_on = [aws_eks_cluster.cluster]
}
