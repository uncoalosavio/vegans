terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }

  required_version = ">= 1.2.0"
}

provider "aws" {
  region = "eu-central-1"
}

# Variables
variable "project_name" {
  description = "The project name"
  type        = string
}

variable "https_certificate_arn" {
  description = "HTTPS ACM Certificate"
  type = string
}

variable "env" {
  description = "The environment (e.g., dev, prod)"
  type        = string
}

variable "secret_arn" {
  description = "The ARN of the AWS Secrets Manager secret containing DB credentials"
  type        = string
}

variable "base_domain" {
  description = "The base domain name of the hosted zone"
  type        = string
}

data "aws_route53_zone" "hosted_zone" {
  zone_id = "Z04967803NSF1E9Q518IR"
  name    = var.base_domain
}

output "hosted_zone_name" {
  value = data.aws_route53_zone.hosted_zone.name
}

output "hosted_zone_id" {
  value = data.aws_route53_zone.hosted_zone.zone_id
}


# VPC
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${var.project_name}-vpc-${var.env}"
  }
}

# Subnets
resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.project_name}-public-subnet-${var.env}"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index + 2)
  tags = {
    Name = "${var.project_name}-private-subnet-${var.env}"
  }
}

resource "aws_subnet" "isolated" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index + 4)
  tags = {
    Name = "${var.project_name}-isolated-subnet-${var.env}"
  }
}

# NAT Gateway and EIP
resource "aws_eip" "nat" {
  count = 1
  vpc   = true
}

resource "aws_nat_gateway" "nat" {
  count         = 1
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
}

# Network ACL
resource "aws_network_acl" "main" {
  vpc_id = aws_vpc.main.id
  subnet_ids = aws_subnet.isolated[*].id
  tags = {
    Name = "${var.project_name}-nacl-${var.env}"
  }
}

resource "aws_network_acl_rule" "ingress" {
  network_acl_id = aws_network_acl.main.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

resource "aws_network_acl_rule" "egress" {
  network_acl_id = aws_network_acl.main.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

# Data source to get the secret values from Secrets Manager
data "aws_secretsmanager_secret_version" "db_creds" {
  secret_id = var.secret_arn
}

# Extracting credentials from the secret
locals {
  db_creds = jsondecode(data.aws_secretsmanager_secret_version.db_creds.secret_string)
}

# Database Parameter Group
resource "aws_db_parameter_group" "mysql" {
  name        = "${var.project_name}-db-parameter-group-${var.env}"
  family      = "mysql8.0"
  description = "Parameter group for MySQL 8.0"

  parameter {
    name  = "rds.force_ssl"
    value = "0"
  }
}

# Security Group
resource "aws_security_group" "database" {
  vpc_id = aws_vpc.main.id
  name   = "database-security-group-${var.env}"

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Database Subnet Group
resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-db-subnet-group-${var.env}"
  subnet_ids = aws_subnet.isolated
  description = "Subnet group for ${var.project_name} RDS instance"

  tags = {
    Name = "${var.project_name}-db-subnet-group-${var.env}"
  }
}

# RDS Instance
resource "aws_db_instance" "mysql" {
  identifier            = "enc-${var.project_name}-${var.env}"
  engine                = "mysql"
  engine_version        = "8.0"
  instance_class        = "db.t4g.micro"
  allocated_storage     = 20
  storage_type          = "gp2"
  db_name                  = "encrypted${var.project_name}${var.env}"
  username              = local.db_creds.username
  password              = local.db_creds.password
  parameter_group_name  = aws_db_parameter_group.mysql.name
  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name  = aws_db_subnet_group.main.name
  multi_az              = false
  publicly_accessible   = false
  storage_encrypted     = true
  skip_final_snapshot   = var.env != "prod"

  tags = {
    Name = "encrypted-database-instance-${var.env}"
  }

  lifecycle {
    create_before_destroy = true
  }
}
# ECS Cluster
resource "aws_ecs_cluster" "cluster" {
  name = "${var.project_name}-cluster-${var.env}"
}

# Security Group allowing all outbound traffic
resource "aws_security_group" "allow_all_outbound" {
  vpc_id = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "keycloak-security-group-service-${var.env}"
  }
}


# Keycloak Security Group
resource "aws_security_group" "keycloak_sg" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "keycloak-security-group-${var.env}"
  }
}

# IAM Role for ECS Tasks
resource "aws_iam_role" "ecs_task_role" {
  name = "keycloak-task-role-${var.env}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  ]
}

# IAM Policy for CloudWatch Logs
resource "aws_iam_policy" "ecs_task_execution_policy" {
  name = "ecs-task-execution-policy-${var.env}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
  })
}


# IAM Role for ECS Task Execution
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs-task-execution-role-${var.env}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = [
    aws_iam_policy.ecs_task_execution_policy.arn
  ]
}

# Fargate Task Definition
resource "aws_ecs_task_definition" "keycloak_task" {
  family                   = "keycloak-task-${var.env}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 512
  memory                   = 1024
  task_role_arn            = aws_iam_role.ecs_task_role.arn
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = jsonencode([
    {
      name      = "keycloak-container-${var.env}"
      image     = "quay.io/keycloak/keycloak:22.0.3"
      cpu       = 256
      memory    = 512
      essential = true
      entryPoint = ["/opt/keycloak/bin/kc.sh", "start"]
      environment = [
        {
          name  = "KC_HOSTNAME"
          value = "service.${var.project_name}-${var.env}.${var.base_domain}"
        },
        {
          name  = "KC_HTTP_RELATIVE_PATH"
          value = "/keycloak"
        },
        {
          name  = "KC_DB"
          value = "mysql"
        },
        {
          name  = "KC_DB_URL"
          value = "jdbc:mysql://${aws_db_instance.mysql.endpoint}/keycloak"
        },
        {
          name  = "KC_PROXY"
          value = "edge"
        },
        {
          name  = "KC_HEALTH_ENABLED"
          value = "true"
        }
      ]
      secrets = [
        {
          name      = "KC_DB_USERNAME"
          valueFrom = local.db_creds.passwird
        },
        {
          name      = "KC_DB_PASSWORD"
          valueFrom = local.db_creds.passwird
        }
      ]
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = "/ecs/keycloak-${var.env}"
          awslogs-region        = "us-east-1" # Change to your desired region
          awslogs-stream-prefix = "keycloak"
        }
      }
    }
  ])
}

# Fargate Service
resource "aws_ecs_service" "keycloak_service" {
  name            = "keycloak-service-${var.env}"
  cluster         = aws_ecs_cluster.cluster.id
  task_definition = aws_ecs_task_definition.keycloak_task.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets         = aws_subnet.private
    security_groups = [
      aws_security_group.allow_all_outbound.id,
      aws_security_group.keycloak_sg.id
    ]
    assign_public_ip = false
  }

  tags = {
    Name = "${var.project_name}-keycloak-${var.env}"
  }

  depends_on = [
    aws_ecs_task_definition.keycloak_task,
    aws_security_group.allow_all_outbound,
    aws_security_group.keycloak_sg
  ]
}


# Security Group for ALB
resource "aws_security_group" "alb_sg" {
  name        = "${var.project_name}-alb-sg-${var.env}"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-alb-sg-${var.env}"
  }
}

# Application Load Balancer
resource "aws_lb" "alb" {
  name               = "${var.project_name}-alb-${var.env}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = aws_subnet.public

  tags = {
    Name = "${var.project_name}-alb-${var.env}"
  }
}

# HTTPS Listener
resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.https_certificate_arn
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "404: Not Found"
      status_code  = "404"
    }
  }
}

# Target Group for Keycloak
resource "aws_lb_target_group" "keycloak_target" {
  name        = "keycloak-target-${var.env}"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  health_check {
    path                = "/keycloak/health"
    protocol            = "HTTP"
    port                = "8080"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 5
    matcher             = "200"
  }

  tags = {
    Name = "keycloak-target-${var.env}"
  }
}

# Add Keycloak ECS service to the target group
resource "aws_lb_target_group_attachment" "keycloak_target_attachment" {
  target_group_arn = aws_lb_target_group.keycloak_target.arn
  target_id        = aws_ecs_service.keycloak_service
  port             = 8080
}

# Listener Rule for Keycloak
resource "aws_lb_listener_rule" "keycloak_listener_rule" {
  listener_arn = aws_lb_listener.https_listener.arn
  priority     = 1

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.keycloak_target.arn
  }

  condition {
    path_pattern {
      values = ["/keycloak/*"]
    }
  }
}

# WAF Web ACL
resource "aws_wafv2_web_acl" "web_acl" {
  name        = "${var.project_name}-bot-waf-${var.env}"
  scope       = "REGIONAL"
  description = "WAF for ALB"
  default_action {
    allow {}
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "webACL"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "AWSManagedRulesBotControlRuleSet"
    priority = 0
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesBotControlRuleSet"
      sampled_requests_enabled   = true
    }
  }
}

# WAF Web ACL Association
resource "aws_wafv2_web_acl_association" "web_acl_association" {
  resource_arn = aws_lb.alb.arn
  web_acl_arn  = aws_wafv2_web_acl.web_acl.arn
}

# Route 53 A Record
resource "aws_route53_record" "alb_alias" {
  zone_id = "Z04967803NSF1E9Q518IR"
  name    = "service.${var.project_name}-${var.env}.${var.base_domain}"
  type    = "A"

  alias {
    name                   = aws_lb.alb.dns_name
    zone_id                = aws_lb.alb.zone_id
    evaluate_target_health = false
  }
}
