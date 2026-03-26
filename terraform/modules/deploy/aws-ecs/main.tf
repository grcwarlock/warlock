###############################################################################
# Warlock Deployment — AWS ECS Fargate
# Deploys: FastAPI API + Pipeline Worker + RDS PostgreSQL + ElastiCache Redis
# Enforces: SC-7 (Network Segmentation), SC-28 (Encryption at Rest), AU-2 (Logging)
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
# AU-2: CloudWatch log group for ECS container logs
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${var.name_prefix}-warlock"
  retention_in_days = var.log_retention_days

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-warlock-ecs-logs" })
}

# -----------------------------------------------------------------------------
# SC-7: Security Groups — ALB, ECS Tasks, RDS/Redis
# -----------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name_prefix = "${var.name_prefix}-alb-"
  description = "ALB security group — allows HTTPS inbound"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-alb-sg" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "ecs" {
  name_prefix = "${var.name_prefix}-ecs-"
  description = "ECS tasks security group — allows traffic from ALB only"
  vpc_id      = var.vpc_id

  ingress {
    description     = "HTTP from ALB"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-ecs-sg" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "data" {
  name_prefix = "${var.name_prefix}-data-"
  description = "RDS and ElastiCache security group — allows traffic from ECS only"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from ECS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  ingress {
    description     = "Redis from ECS"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
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
# SC-28: Secrets Manager — JWT secret and database URL
# -----------------------------------------------------------------------------

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  name_prefix = "${var.name_prefix}-wlk-jwt-"
  description = "Warlock JWT signing secret"

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-jwt-secret" })
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id     = aws_secretsmanager_secret.jwt_secret.id
  secret_string = var.wlk_jwt_secret
}

resource "aws_secretsmanager_secret" "db_url" {
  name_prefix = "${var.name_prefix}-wlk-db-url-"
  description = "Warlock database connection URL"

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-db-url-secret" })
}

resource "aws_secretsmanager_secret_version" "db_url" {
  secret_id = aws_secretsmanager_secret.db_url.id
  secret_string = format(
    "postgresql://%s:%s@%s:5432/%s",
    var.db_username,
    random_password.db_password.result,
    aws_db_instance.warlock.address,
    var.db_name
  )
}

# -----------------------------------------------------------------------------
# SC-28: RDS PostgreSQL — encrypted, Multi-AZ
# -----------------------------------------------------------------------------

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

  db_name  = var.db_name
  username = var.db_username
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
# ECS Cluster — Container Insights enabled (AU-2)
# -----------------------------------------------------------------------------

resource "aws_ecs_cluster" "warlock" {
  name = "${var.name_prefix}-warlock"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"

      log_configuration {
        cloud_watch_log_group_name = aws_cloudwatch_log_group.ecs.name
      }
    }
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-warlock-cluster" })
}

resource "aws_ecs_cluster_capacity_providers" "warlock" {
  cluster_name = aws_ecs_cluster.warlock.name

  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 0
  }
}

# -----------------------------------------------------------------------------
# IAM — Task execution role + task role
# -----------------------------------------------------------------------------

resource "aws_iam_role" "ecs_execution" {
  name_prefix = "${var.name_prefix}-ecs-exec-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-ecs-execution-role" })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name_prefix = "${var.name_prefix}-secrets-"
  role        = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue"
      ]
      Resource = [
        aws_secretsmanager_secret.jwt_secret.arn,
        aws_secretsmanager_secret.db_url.arn,
      ]
    }]
  })
}

resource "aws_iam_role" "ecs_task" {
  name_prefix = "${var.name_prefix}-ecs-task-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-ecs-task-role" })
}

# -----------------------------------------------------------------------------
# ECS Task Definition — 2 containers: warlock-api + warlock-worker
# -----------------------------------------------------------------------------

locals {
  redis_url = format(
    "rediss://:%s@%s:6379/0",
    random_password.redis_auth.result,
    aws_elasticache_replication_group.warlock.primary_endpoint_address
  )

  shared_environment = [
    { name = "WLK_AI_ENABLED", value = var.wlk_ai_enabled },
    { name = "WLK_OPA_URL", value = var.wlk_opa_url },
    { name = "WLK_REDIS_URL", value = local.redis_url },
  ]

  shared_secrets = [
    {
      name      = "WLK_JWT_SECRET"
      valueFrom = aws_secretsmanager_secret.jwt_secret.arn
    },
    {
      name      = "WLK_DATABASE_URL"
      valueFrom = aws_secretsmanager_secret.db_url.arn
    },
  ]
}

resource "aws_ecs_task_definition" "warlock" {
  family                   = "${var.name_prefix}-warlock"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "warlock-api"
      image     = var.container_image
      essential = true

      portMappings = [{
        containerPort = 8000
        protocol      = "tcp"
      }]

      environment = local.shared_environment
      secrets     = local.shared_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "api"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:8000/health || exit 1"]
        interval    = 15
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
    },
    {
      name      = "warlock-worker"
      image     = var.container_image
      essential = true

      command = ["python", "-m", "warlock.pipeline.scheduler"]

      environment = local.shared_environment
      secrets     = local.shared_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "worker"
        }
      }
    },
  ])

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-warlock-task" })
}

# -----------------------------------------------------------------------------
# ALB — HTTPS listener with health check on /health
# -----------------------------------------------------------------------------

resource "aws_lb" "warlock" {
  name_prefix        = "wlk-"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = !var.skip_final_snapshot

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-warlock-alb" })
}

resource "aws_lb_target_group" "warlock" {
  name_prefix = "wlk-"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 15
    timeout             = 5
    matcher             = "200"
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-warlock-tg" })
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.warlock.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.warlock.arn
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-warlock-listener" })
}

# -----------------------------------------------------------------------------
# ECS Service — deployment circuit breaker enabled
# -----------------------------------------------------------------------------

resource "aws_ecs_service" "warlock" {
  name            = "${var.name_prefix}-warlock"
  cluster         = aws_ecs_cluster.warlock.id
  task_definition = aws_ecs_task_definition.warlock.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.warlock.arn
    container_name   = "warlock-api"
    container_port   = 8000
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-warlock-service" })

  depends_on = [aws_lb_listener.https]
}

# -----------------------------------------------------------------------------
# Warlock closed-loop registration
# -----------------------------------------------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "deploy/aws-ecs"
  resource_id    = aws_ecs_cluster.warlock.arn
  control_ids    = ["SC-7", "SC-28", "AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    desired_count   = tostring(var.desired_count)
    cpu             = tostring(var.cpu)
    memory          = tostring(var.memory)
    db_multi_az     = "true"
    redis_encrypted = "true"
  }
}
