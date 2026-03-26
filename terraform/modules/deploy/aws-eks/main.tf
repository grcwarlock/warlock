###############################################################################
# Warlock Deployment — AWS EKS
# Deploys: EKS Cluster + Node Group + RDS PostgreSQL + ElastiCache Redis
# Application deployment via Helm chart from deploy/kubernetes-helm/
# Enforces: SC-7 (Network Segmentation), SC-28 (Encryption at Rest),
#           AC-3 (Access Enforcement)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  common_tags = merge(var.tags, {
    ManagedBy   = "warlock"
    Environment = var.environment
    Team        = var.team
    Framework   = "NIST-800-53"
  })
}

# -----------------------------------------------------------------------------
# SC-7: Security Groups — EKS Cluster, Node Group, Data tier
# -----------------------------------------------------------------------------

resource "aws_security_group" "cluster" {
  name_prefix = "${var.name_prefix}-eks-cluster-"
  description = "EKS cluster control plane security group"
  vpc_id      = var.vpc_id

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-eks-cluster-sg" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "node" {
  name_prefix = "${var.name_prefix}-eks-node-"
  description = "EKS worker node security group"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Cluster API to nodes"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id]
  }

  ingress {
    description     = "Cluster API to kubelet"
    from_port       = 10250
    to_port         = 10250
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id]
  }

  ingress {
    description = "Node to node communication"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name                                               = "${var.name_prefix}-eks-node-sg"
    "kubernetes.io/cluster/${var.name_prefix}-warlock" = "owned"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "cluster_ingress_nodes" {
  description              = "Nodes to cluster API"
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.node.id
  security_group_id        = aws_security_group.cluster.id
}

resource "aws_security_group" "data" {
  name_prefix = "${var.name_prefix}-data-"
  description = "RDS and ElastiCache security group — allows traffic from EKS nodes only"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from EKS nodes"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.node.id]
  }

  ingress {
    description     = "Redis from EKS nodes"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.node.id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-data-sg" })

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------------------------------------------------------
# AC-3: EKS Cluster IAM Role
# -----------------------------------------------------------------------------

resource "aws_iam_role" "eks_cluster" {
  name_prefix = "${var.name_prefix}-eks-cluster-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-eks-cluster-role" })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_vpc_resource_controller" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
}

# -----------------------------------------------------------------------------
# SC-28, AC-3: EKS Cluster — secrets encryption enabled
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/${var.name_prefix}-warlock/cluster"
  retention_in_days = var.log_retention_days

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-eks-logs" })
}

resource "aws_kms_key" "eks_secrets" {
  description             = "KMS key for EKS secret envelope encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-eks-secrets-key" })
}

resource "aws_kms_alias" "eks_secrets" {
  name          = "alias/${var.name_prefix}-eks-secrets"
  target_key_id = aws_kms_key.eks_secrets.key_id
}

resource "aws_eks_cluster" "warlock" {
  name     = "${var.name_prefix}-warlock"
  version  = var.kubernetes_version
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    security_group_ids      = [aws_security_group.cluster.id]
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-warlock-eks" })

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_resource_controller,
    aws_cloudwatch_log_group.eks,
  ]
}

# -----------------------------------------------------------------------------
# AC-3: EKS Node Group IAM Role
# -----------------------------------------------------------------------------

resource "aws_iam_role" "eks_node" {
  name_prefix = "${var.name_prefix}-eks-node-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-eks-node-role" })
}

resource "aws_iam_role_policy_attachment" "eks_node_policy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks_ecr_policy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# -----------------------------------------------------------------------------
# EKS Node Group
# -----------------------------------------------------------------------------

resource "aws_eks_node_group" "warlock" {
  cluster_name    = aws_eks_cluster.warlock.name
  node_group_name = "${var.name_prefix}-warlock-nodes"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = var.private_subnet_ids

  instance_types = var.node_instance_types

  scaling_config {
    min_size     = var.node_min_size
    max_size     = var.node_max_size
    desired_size = var.node_desired_size
  }

  update_config {
    max_unavailable = 1
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-warlock-nodes" })

  depends_on = [
    aws_iam_role_policy_attachment.eks_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_ecr_policy,
  ]
}

# -----------------------------------------------------------------------------
# EKS Addons — vpc-cni, coredns, kube-proxy
# -----------------------------------------------------------------------------

resource "aws_eks_addon" "vpc_cni" {
  cluster_name = aws_eks_cluster.warlock.name
  addon_name   = "vpc-cni"

  resolve_conflicts_on_update = "OVERWRITE"

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-vpc-cni" })
}

resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.warlock.name
  addon_name   = "coredns"

  resolve_conflicts_on_update = "OVERWRITE"

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-coredns" })

  depends_on = [aws_eks_node_group.warlock]
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name = aws_eks_cluster.warlock.name
  addon_name   = "kube-proxy"

  resolve_conflicts_on_update = "OVERWRITE"

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-kube-proxy" })
}

# -----------------------------------------------------------------------------
# SC-28: RDS PostgreSQL — encrypted, Multi-AZ
# -----------------------------------------------------------------------------

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "aws_db_subnet_group" "warlock" {
  name_prefix = "${var.name_prefix}-warlock-"
  description = "Warlock RDS subnet group"
  subnet_ids  = var.private_subnet_ids

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-db-subnet-group" })
}

resource "aws_db_instance" "warlock" {
  identifier_prefix = "${var.name_prefix}-warlock-"

  engine         = "postgres"
  engine_version = "15"
  instance_class = var.db_instance_class

  db_name  = "warlock"
  username = "warlock"
  password = random_password.db_password.result

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_encrypted     = true

  multi_az               = true
  db_subnet_group_name   = aws_db_subnet_group.warlock.name
  vpc_security_group_ids = [aws_security_group.data.id]

  backup_retention_period   = 7
  skip_final_snapshot       = var.skip_final_snapshot
  final_snapshot_identifier = var.skip_final_snapshot ? null : "${var.name_prefix}-warlock-final"

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-warlock-db" })
}

# -----------------------------------------------------------------------------
# SC-28: ElastiCache Redis — encrypted, auth token
# -----------------------------------------------------------------------------

resource "random_password" "redis_auth" {
  length  = 32
  special = false
}

resource "aws_elasticache_subnet_group" "warlock" {
  name       = "${var.name_prefix}-warlock-redis"
  subnet_ids = var.private_subnet_ids

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-redis-subnet-group" })
}

resource "aws_elasticache_replication_group" "warlock" {
  replication_group_id = "${var.name_prefix}-warlock"
  description          = "Warlock Redis cluster"

  engine         = "redis"
  engine_version = "7.0"
  node_type      = "cache.t3.micro"

  num_cache_clusters = 2

  subnet_group_name  = aws_elasticache_subnet_group.warlock.name
  security_group_ids = [aws_security_group.data.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_auth.result

  automatic_failover_enabled = true

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-warlock-redis" })
}

# -----------------------------------------------------------------------------
# Note: Warlock application deployment uses the Helm chart from
# deploy/kubernetes-helm/. After this module provisions the cluster and
# data tier, use helm_release or kubectl to deploy the Warlock chart
# pointing at the RDS and ElastiCache endpoints exposed as outputs.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Warlock closed-loop registration
# -----------------------------------------------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "deploy/aws-eks"
  resource_id    = aws_eks_cluster.warlock.arn
  control_ids    = ["SC-7", "SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    kubernetes_version = var.kubernetes_version
    node_min_size      = tostring(var.node_min_size)
    node_max_size      = tostring(var.node_max_size)
    secrets_encrypted  = "true"
    db_multi_az        = "true"
    redis_encrypted    = "true"
  }
}
