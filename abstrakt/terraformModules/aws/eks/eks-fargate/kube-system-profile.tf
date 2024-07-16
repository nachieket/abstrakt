resource "aws_iam_role" "eks-fargate-profile" {
  name = "eks-fargate-profile${var.random_string}"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks-fargate-pods.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "eks-fargate-profile" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
  role       = aws_iam_role.eks-fargate-profile.name
}

resource "aws_eks_fargate_profile" "kube-system" {
  cluster_name           = aws_eks_cluster.cluster.name
  fargate_profile_name   = "kube-system"
  pod_execution_role_arn = aws_iam_role.eks-fargate-profile.arn

  # These subnets must have the following resource tag:
  # kubernetes.io/cluster/<CLUSTER_NAME>.
  subnet_ids = [
    aws_subnet.private-subnet-a.id,
    aws_subnet.private-subnet-b.id
  ]

  selector {
    namespace = "kube-system"
  }
}

resource "aws_eks_fargate_profile" "default" {
  cluster_name           = aws_eks_cluster.cluster.name
  fargate_profile_name   = "default"
  pod_execution_role_arn = aws_iam_role.eks-fargate-profile.arn

  # These subnets must have the following resource tag:
  # kubernetes.io/cluster/<CLUSTER_NAME>.
  subnet_ids = [
    aws_subnet.private-subnet-a.id,
    aws_subnet.private-subnet-b.id
  ]

  selector {
    namespace = "default"
  }
}

resource "aws_eks_fargate_profile" "falcon-system" {
  cluster_name           = aws_eks_cluster.cluster.name
  fargate_profile_name   = "falcon-system"
  pod_execution_role_arn = aws_iam_role.eks-fargate-profile.arn

  # These subnets must have the following resource tag:
  # kubernetes.io/cluster/<CLUSTER_NAME>.
  subnet_ids = [
    aws_subnet.private-subnet-a.id,
    aws_subnet.private-subnet-b.id
  ]

  selector {
    namespace = "falcon-system"
  }
}

resource "aws_eks_fargate_profile" "falcon-kac" {
  cluster_name           = aws_eks_cluster.cluster.name
  fargate_profile_name   = "falcon-kac"
  pod_execution_role_arn = aws_iam_role.eks-fargate-profile.arn

  # These subnets must have the following resource tag:
  # kubernetes.io/cluster/<CLUSTER_NAME>.
  subnet_ids = [
    aws_subnet.private-subnet-a.id,
    aws_subnet.private-subnet-b.id
  ]

  selector {
    namespace = "falcon-kac"
  }
}

resource "aws_eks_fargate_profile" "falcon-image-analyzer" {
  cluster_name           = aws_eks_cluster.cluster.name
  fargate_profile_name   = "falcon-image-analyzer"
  pod_execution_role_arn = aws_iam_role.eks-fargate-profile.arn

  # These subnets must have the following resource tag:
  # kubernetes.io/cluster/<CLUSTER_NAME>.
  subnet_ids = [
    aws_subnet.private-subnet-a.id,
    aws_subnet.private-subnet-b.id
  ]

  selector {
    namespace = "falcon-image-analyzer"
  }
}

resource "aws_eks_fargate_profile" "falcon-kubernetes-protection" {
  cluster_name           = aws_eks_cluster.cluster.name
  fargate_profile_name   = "falcon-kubernetes-protection"
  pod_execution_role_arn = aws_iam_role.eks-fargate-profile.arn

  # These subnets must have the following resource tag:
  # kubernetes.io/cluster/<CLUSTER_NAME>.
  subnet_ids = [
    aws_subnet.private-subnet-a.id,
    aws_subnet.private-subnet-b.id
  ]

  selector {
    namespace = "falcon-kubernetes-protection"
  }
}

resource "aws_eks_fargate_profile" "crowdstrike-detections" {
  cluster_name           = aws_eks_cluster.cluster.name
  fargate_profile_name   = "crowdstrike-detections"
  pod_execution_role_arn = aws_iam_role.eks-fargate-profile.arn

  # These subnets must have the following resource tag:
  # kubernetes.io/cluster/<CLUSTER_NAME>.
  subnet_ids = [
    aws_subnet.private-subnet-a.id,
    aws_subnet.private-subnet-b.id
  ]

  selector {
    namespace = "crowdstrike-detections"
  }
}

resource "aws_eks_fargate_profile" "ns1" {
  cluster_name           = aws_eks_cluster.cluster.name
  fargate_profile_name   = "ns1"
  pod_execution_role_arn = aws_iam_role.eks-fargate-profile.arn

  # These subnets must have the following resource tag:
  # kubernetes.io/cluster/<CLUSTER_NAME>.
  subnet_ids = [
    aws_subnet.private-subnet-a.id,
    aws_subnet.private-subnet-b.id
  ]

  selector {
    namespace = "ns1"
  }
}

resource "aws_eks_fargate_profile" "ns2" {
  cluster_name           = aws_eks_cluster.cluster.name
  fargate_profile_name   = "ns2"
  pod_execution_role_arn = aws_iam_role.eks-fargate-profile.arn

  # These subnets must have the following resource tag:
  # kubernetes.io/cluster/<CLUSTER_NAME>.
  subnet_ids = [
    aws_subnet.private-subnet-a.id,
    aws_subnet.private-subnet-b.id
  ]

  selector {
    namespace = "ns2"
  }
}
