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
  region  = "eu-central-1"
}

resource "aws_vpc" "cloudx" {
  cidr_block = "10.10.0.0/16"
  enable_dns_support = "true"
  enable_dns_hostnames = "true"
  tags = {
    Name = "cloudx"
  }
}

resource "aws_internet_gateway" "cloudx-igw" {
  vpc_id = aws_vpc.cloudx.id
  tags = {
    Name = "cloudx-igw"
  }
}

resource "aws_subnet" "public_a" {
  vpc_id     = aws_vpc.cloudx.id
  cidr_block = "10.10.1.0/24"
  availability_zone = "eu-central-1a"
  tags = {
    Name = "public_a"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id     = aws_vpc.cloudx.id
  cidr_block = "10.10.2.0/24"
  availability_zone = "eu-central-1b"
  tags = {
    Name = "public_b"
  }
}

resource "aws_subnet" "public_c" {
  vpc_id     = aws_vpc.cloudx.id
  cidr_block = "10.10.3.0/24"
  availability_zone = "eu-central-1c"
  tags = {
    Name = "public_c"
  }
}

resource "aws_subnet" "private_a" {
  vpc_id     = aws_vpc.cloudx.id
  cidr_block = "10.10.10.0/24"
  availability_zone = "eu-central-1a"
  tags = {
    Name = "private_a"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id     = aws_vpc.cloudx.id
  cidr_block = "10.10.11.0/24"
  availability_zone = "eu-central-1b"
  tags = {
    Name = "private_b"
  }
}

resource "aws_subnet" "private_c" {
  vpc_id     = aws_vpc.cloudx.id
  cidr_block = "10.10.12.0/24"
  availability_zone = "eu-central-1c"
  tags = {
    Name = "private_c"
  }
}

resource "aws_subnet" "private_db_a" {
  vpc_id     = aws_vpc.cloudx.id
  cidr_block = "10.10.20.0/24"
  availability_zone = "eu-central-1a"
  tags = {
    Name = "private_db_a"
  }
}

resource "aws_subnet" "private_db_b" {
  vpc_id     = aws_vpc.cloudx.id
  cidr_block = "10.10.21.0/24"
  availability_zone = "eu-central-1b"
  tags = {
    Name = "private_db_b"
  }
}

resource "aws_subnet" "private_db_c" {
  vpc_id     = aws_vpc.cloudx.id
  cidr_block = "10.10.22.0/24"
  availability_zone = "eu-central-1c"
  tags = {
    Name = "private_db_c"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.cloudx.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cloudx-igw.id
  }
  tags = {
    Name = "public_rt"
  }
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.cloudx.id
  tags = {
    Name = "private_rt"
  }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_c" {
  subnet_id      = aws_subnet.public_c.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_c" {
  subnet_id      = aws_subnet.private_c.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_db_a" {
  subnet_id      = aws_subnet.private_db_a.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_db_b" {
  subnet_id      = aws_subnet.private_db_b.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_db_c" {
  subnet_id      = aws_subnet.private_db_c.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_security_group" "bastion" {
  name        = "bastion"
  description = "allows access to bastion"
  vpc_id      = aws_vpc.cloudx.id
  ingress {
    description      = "rule_1"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["86.57.156.212/32"]
  }
  egress {
    description      = "rule_1"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }
  tags = {
    Name = "bastion"
  }
}

resource "aws_security_group" "ec2_pool" {
  name        = "ec2_pool"
  description = "allows access to ec2 instances"
  vpc_id      = aws_vpc.cloudx.id
  ingress {
    description      = "rule_1_bastion"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    security_groups  = [aws_security_group.bastion.id]
  }
  ingress {
    description      = "rule_2_alb"
    from_port        = 2368
    to_port          = 2368
    protocol         = "tcp"
    security_groups  = [aws_security_group.alb.id]
  }
  ingress {
    description      = "rule_3_efs"
    from_port        = 2049
    to_port          = 2049
    protocol         = "tcp"
    cidr_blocks      = [aws_vpc.cloudx.cidr_block]
  }
  egress {
    description      = "rule_1"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }
  tags = {
    Name = "ec2_pool"
  }
}

resource "aws_security_group" "fargate_pool" {
  name        = "fargate_pool"
  description = "Allows access for Fargate instances"
  vpc_id      = aws_vpc.cloudx.id
  ingress {
    description      = "rule_1_alb"
    from_port        = 2368
    to_port          = 2368
    protocol         = "tcp"
    security_groups  = [aws_security_group.alb.id]
  }
  ingress {
    description      = "rule_2_efs"
    from_port        = 2049
    to_port          = 2049
    protocol         = "tcp"
    # security_groups  = [aws_security_group.efs.id]
    cidr_blocks      = [aws_vpc.cloudx.cidr_block]
  }
  egress {
    description      = "rule_1"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }
  tags = {
    Name = "fargate_pool"
  }
}

resource "aws_security_group" "alb" {
  name        = "alb"
  description = "allows access to alb"
  vpc_id      = aws_vpc.cloudx.id
  ingress {
    description      = "rule_1"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["86.57.156.212/32"]
  }
  egress {
    description      = "rule_1"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = [aws_vpc.cloudx.cidr_block]
  }
  tags = {
    Name = "alb"
  }
}

resource "aws_security_group" "efs" {
  name        = "efs"
  description = "defines access to efs mount points"
  vpc_id      = aws_vpc.cloudx.id
  ingress {
    description      = "rule_1"
    from_port        = 2049
    to_port          = 2049
    protocol         = "tcp"
    security_groups  = [aws_security_group.ec2_pool.id]
  }
  ingress {
    description      = "rule_2"
    from_port        = 2049
    to_port          = 2049
    protocol         = "tcp"
    security_groups  = [aws_security_group.fargate_pool.id]
  }
  egress {
    description      = "rule_1"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = [aws_vpc.cloudx.cidr_block]
  }
  tags = {
    Name = "efs"
  }
}

resource "aws_security_group" "mysql" {
  name        = "mysql"
  description = "defines access to ghost db"
  vpc_id      = aws_vpc.cloudx.id
  ingress {
    description      = "rule_1"
    from_port        = 3306
    to_port          = 3306
    protocol         = "tcp"
    security_groups  = [aws_security_group.ec2_pool.id]
  }
  ingress {
    description      = "rule_2"
    from_port        = 3306
    to_port          = 3306
    protocol         = "tcp"
    security_groups  = [aws_security_group.fargate_pool.id]
  }
  egress {
    description      = "rule_1"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = [aws_vpc.cloudx.cidr_block]
  }
  tags = {
    Name = "mysql"
  }
}

resource "aws_security_group" "vpc-ep" {
  name        = "vpc-ep"
  description = "allows access to vpc endpoints"
  vpc_id      = aws_vpc.cloudx.id
  ingress {
    description      = "rule_1"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }
  egress {
    description      = "rule_1"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }
  tags = {
    Name = "vpc-ep"
  }
}

resource "aws_key_pair" "ghost-ec2-pool" {
  key_name   = "ghost-ec2-pool"
  public_key = var.public_key
}

resource "aws_iam_policy" "cloudx_ec2_policy" {
  name = "cloudx_ec2_policy"
  path = "/"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "ec2:Describe*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
   })
}

resource "aws_iam_policy" "cloudx_efs_policy" {
  name = "cloudx_efs_policy"
  path = "/"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = [
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite",
                "elasticfilesystem:DescribeFileSystems"
                ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
   })
}

resource "aws_iam_policy" "cloudx_rds_policy" {
  name = "cloudx_rds_policy"
  path = "/"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = [
                "ecr:*",
                "ecs:*",
                "ssm:*",
                "logs:*",
                "ssmmessages:*",
                "elasticfilesystem:*",
                "rds:*",
                "rds:DescribeDBInstances",
                "ssm:GetParameter*",
                "secretsmanager:GetSecretValue",
                "elasticloadbalancing:Describe*",
                "logs:*",
                "kms:Decrypt"
                ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
   })
}

resource "aws_iam_policy" "cloudx_ecs_policy" {
  name = "cloudx_ecs_policy"
  path = "/"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = [
                "ecr:*",
                "ecs:*",
                "ssm:*",
                "logs:*",
                "ssmmessages:*",
                "elasticfilesystem:*",
                "rds:*",
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "elasticfilesystem:DescribeFileSystems",
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite"
                ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
   })
}

resource "aws_iam_role" "ghost_app_role" {
  name        = "ghost_app_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role" "ghost_ecs_role" {
  name        = "ghost_ecs_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudx_ec2_policy_attachment" {
  role       = aws_iam_role.ghost_app_role.name
  policy_arn = aws_iam_policy.cloudx_ec2_policy.arn
}

resource "aws_iam_role_policy_attachment" "cloudx_efs_policy_attachment" {
  role       = aws_iam_role.ghost_app_role.name
  policy_arn = aws_iam_policy.cloudx_efs_policy.arn
}

resource "aws_iam_role_policy_attachment" "cloudx_rds_policy_attachment" {
  role       = aws_iam_role.ghost_app_role.name
  policy_arn = aws_iam_policy.cloudx_rds_policy.arn
}

resource "aws_iam_role_policy_attachment" "cloudx_ecs_policy_attachment" {
  role       = aws_iam_role.ghost_ecs_role.name
  policy_arn = aws_iam_policy.cloudx_ecs_policy.arn
}

resource "aws_iam_instance_profile" "ghost_app_profile" {
  name = "ghost_app"
  role = aws_iam_role.ghost_app_role.name
}

resource "aws_iam_instance_profile" "ghost_ecs_profile" {
  name = "ghost_ecs"
  role = aws_iam_role.ghost_app_role.name
}

resource "aws_efs_file_system" "ghost_content" {
  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
  tags = {
    Name = "ghost_content"
  }
}

resource "aws_efs_backup_policy" "policy" {
  file_system_id = aws_efs_file_system.ghost_content.id
  backup_policy {
    status = "DISABLED"
  }
}

resource "aws_efs_mount_target" "efs_mount_target_a" {
  file_system_id = aws_efs_file_system.ghost_content.id
  subnet_id      = aws_subnet.public_a.id
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_mount_target" "efs_mount_target_b" {
  file_system_id = aws_efs_file_system.ghost_content.id
  subnet_id      = aws_subnet.public_b.id
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_mount_target" "efs_mount_target_c" {
  file_system_id = aws_efs_file_system.ghost_content.id
  subnet_id      = aws_subnet.public_c.id
  security_groups = [aws_security_group.efs.id]
}

resource "aws_lb" "cloudx-alb" {
  name               = "cloudx-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [
                    aws_subnet.public_a.id,
                    aws_subnet.public_b.id,
                    aws_subnet.public_c.id,
                    ]
}

resource "aws_lb_target_group" "ghost-ec2" {
  name     = "ghost-ec2"
  port     = 2368
  protocol = "HTTP"
  vpc_id   = aws_vpc.cloudx.id
}

resource "aws_lb_target_group" "ghost-fargate" {
  name     = "ghost-fargate"
  port     = 2368
  protocol = "HTTP"
  target_type = "ip"
  vpc_id   = aws_vpc.cloudx.id
}

resource "aws_lb_listener" "cloudx-alb-listener" {
  load_balancer_arn = aws_lb.cloudx-alb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    forward {
      target_group {
        arn = aws_lb_target_group.ghost-ec2.arn
        weight = 500
      }
      target_group {
        arn = aws_lb_target_group.ghost-fargate.arn
        weight = 500
      }
    }
  }
}

resource "aws_launch_template" "ghost" {
  name = "ghost"
  instance_type = "t2.micro"
  # image_id = "ami-03f710e174aa82316"
  image_id = "ami-06616b7884ac98cdd"
  monitoring {
    enabled = true
  }
  iam_instance_profile {
    name = aws_iam_instance_profile.ghost_app_profile.name
  }
  network_interfaces {
    associate_public_ip_address = true
    delete_on_termination       = true
    security_groups = [aws_security_group.ec2_pool.id]
  }
  key_name = aws_key_pair.ghost-ec2-pool.key_name
  user_data = filebase64("${path.module}/init_with_db.sh")
}

resource "aws_autoscaling_group" "ghost_ec2_pool" {
  depends_on      = [
                    aws_efs_file_system.ghost_content,
                    aws_db_instance.ghost
                    ]
  name = "ghost_ec2_pool"
  vpc_zone_identifier  = [aws_subnet.public_a.id, aws_subnet.public_b.id, aws_subnet.public_c.id]
  desired_capacity   = 1
  max_size           = 3
  min_size           = 1
  launch_template {
    id      = aws_launch_template.ghost.id
    version = "$Latest"
  }
  target_group_arns = [aws_lb_target_group.ghost-ec2.arn]
}

resource "aws_autoscaling_policy" "ghost_asp" {
  name                   = "ghost_asp"
  autoscaling_group_name = aws_autoscaling_group.ghost_ec2_pool.name
  policy_type            = "TargetTrackingScaling"
  estimated_instance_warmup = 300
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 50.0
  }
}

resource "aws_network_interface" "bastion" {
  private_ips = ["10.10.1.10"]
  subnet_id   = aws_subnet.public_a.id
  security_groups = [aws_security_group.bastion.id]
  tags = {
    Name = "primary_network_interface"
  }
}

resource "aws_instance" "bastion" {
  depends_on = [aws_security_group.bastion]
  # ami           = "ami-03f710e174aa82316"
  ami           = "ami-06616b7884ac98cdd"
  instance_type = "t2.micro"
  monitoring = true
  key_name = aws_key_pair.ghost-ec2-pool.key_name
  # associate_public_ip_address = true
  # subnet_id = aws_subnet.public_a.id
  # security_groups = [aws_security_group.bastion.id]
  network_interface {
    network_interface_id = aws_network_interface.bastion.id
    device_index         = 0
  }
  tags = {
    Name = "bastion"
  }
}

#**************************************************************************************************************************

resource "aws_db_subnet_group" "mysql" {
  name       = "mysql"
  description = "ghost database subnet group"
  subnet_ids = [aws_subnet.private_db_a.id, aws_subnet.private_db_b.id, aws_subnet.private_db_c.id]
  tags = {
    Name = "mysql"
  }
}

variable "db_password" {
  description = "Database administrator password"
  type        = string
  sensitive   = true
}

variable "public_key" {
  description = "Instances ssh public key"
  type        = string
  sensitive   = true
}

resource "aws_db_instance" "ghost" {
  allocated_storage        = 10
  max_allocated_storage    = 20
  storage_type             = "gp2"
  db_name                  = "ghost"
  username                 = "db_user"
  password                 = var.db_password
  engine                   = "mysql"
  engine_version           = "8.0"
  instance_class           = "db.t2.micro"
  vpc_security_group_ids   = [aws_security_group.mysql.id]
  db_subnet_group_name     = aws_db_subnet_group.mysql.name
  skip_final_snapshot      = true
  delete_automated_backups = true
  monitoring_interval = 5
  monitoring_role_arn = "arn:aws:iam::147977937220:role/rds-monitoring-role"
}

resource "aws_ssm_parameter" "db_password" {
  name        = "/ghost/dbpassw"
  description = "The parameter description"
  type        = "SecureString"
  value       = var.db_password
}

# *************************************************************************************************************

resource "aws_ecr_repository" "ghost" {
  name                 = "ghost"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_ecs_cluster" "ghost" {
  name = "ghost"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_vpc_endpoint" "cloudx-ecs-efs-ep-i" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.eu-central-1.elasticfilesystem"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  dns_options {
    dns_record_ip_type = "ipv4"
  }
  ip_address_type = "ipv4"
  subnet_ids          = [
                      aws_subnet.private_a.id,
                      aws_subnet.private_b.id,
                      aws_subnet.private_c.id
                      ]
  security_group_ids = [aws_security_group.vpc-ep.id]
  tags = {
    Name = "cloudx-ecs-efs-ep-i"
  }
}

resource "aws_vpc_endpoint" "cloudx-ecs-ecr-api-ep-i" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.eu-central-1.ecr.api"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  dns_options {
    dns_record_ip_type = "ipv4"
  }
  ip_address_type = "ipv4"
  subnet_ids          = [
                      aws_subnet.private_a.id,
                      aws_subnet.private_b.id,
                      aws_subnet.private_c.id
                      ]
  security_group_ids = [aws_security_group.vpc-ep.id]
  tags = {
    Name = "cloudx-ecs-ecr-api-ep-i"
  }
}

resource "aws_vpc_endpoint" "cloudx-ecs-ecr-drk-ep-i" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.eu-central-1.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  dns_options {
    dns_record_ip_type = "ipv4"
  }
  ip_address_type = "ipv4"
  subnet_ids          = [
                      aws_subnet.private_a.id,
                      aws_subnet.private_b.id,
                      aws_subnet.private_c.id
                      ]
  security_group_ids = [aws_security_group.vpc-ep.id]
  tags = {
    Name = "cloudx-ecs-ecr-drk-ep-i"
  }
}

resource "aws_vpc_endpoint" "cloudx-ecs-ssm-ep-i" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.eu-central-1.ssm"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  dns_options {
    dns_record_ip_type = "ipv4"
  }
  ip_address_type = "ipv4"
  subnet_ids          = [
                      aws_subnet.private_a.id,
                      aws_subnet.private_b.id,
                      aws_subnet.private_c.id
                      ]
  security_group_ids = [aws_security_group.vpc-ep.id]
  tags = {
    Name = "cloudx-ecs-ssm-ep-i"
  }
}

resource "aws_vpc_endpoint" "cloudx-ecs-ssmmessages-ep-i" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.eu-central-1.ssmmessages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  dns_options {
    dns_record_ip_type = "ipv4"
  }
  ip_address_type = "ipv4"
  subnet_ids          = [
                      aws_subnet.private_a.id,
                      aws_subnet.private_b.id,
                      aws_subnet.private_c.id
                      ]
  security_group_ids = [aws_security_group.vpc-ep.id]
  tags = {
    Name = "cloudx-ecs-ssmmessages-ep-i"
  }
}

resource "aws_vpc_endpoint" "cloudx-ecs-ec2messages-ep-i" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.eu-central-1.ec2messages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  dns_options {
    dns_record_ip_type = "ipv4"
  }
  ip_address_type = "ipv4"
  subnet_ids          = [
                      aws_subnet.private_a.id,
                      aws_subnet.private_b.id,
                      aws_subnet.private_c.id
                      ]
  security_group_ids = [aws_security_group.vpc-ep.id]
  tags = {
    Name = "cloudx-ecs-ec2messages-ep-i"
  }
}

resource "aws_vpc_endpoint" "cloudx-ecs-logs-ep-i" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.eu-central-1.logs"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  dns_options {
    dns_record_ip_type = "ipv4"
  }
  ip_address_type = "ipv4"
  subnet_ids          = [
                      aws_subnet.private_a.id,
                      aws_subnet.private_b.id,
                      aws_subnet.private_c.id
                      ]
  security_group_ids = [aws_security_group.vpc-ep.id]
  tags = {
    Name = "cloudx-ecs-logs-ep-i"
  }
}

resource "aws_vpc_endpoint" "cloudx-ecs-monitoring-ep-i" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.eu-central-1.monitoring"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  dns_options {
    dns_record_ip_type = "ipv4"
  }
  ip_address_type = "ipv4"
  subnet_ids          = [
                      aws_subnet.private_a.id,
                      aws_subnet.private_b.id,
                      aws_subnet.private_c.id
                      ]
  security_group_ids = [aws_security_group.vpc-ep.id]
  tags = {
    Name = "cloudx-ecs-monitoring-ep-i"
  }
}

resource "aws_vpc_endpoint" "cloudx-ecs-s3-ep-gw" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.eu-central-1.s3"
  vpc_endpoint_type   = "Gateway"
  route_table_ids     = [aws_route_table.private_rt.id]
  tags = {
    Name = "cloudx-ecs-s3-ep-gw"
  }
}

resource "aws_ecs_task_definition" "task_def_ghost" {
  family = "ghost"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 1024
  execution_role_arn       = aws_iam_role.ghost_ecs_role.arn
  task_role_arn            = aws_iam_role.ghost_ecs_role.arn
  volume {
    name = "ghost_volume"
    efs_volume_configuration {
      file_system_id = aws_efs_file_system.ghost_content.id
    }
  }
  container_definitions = jsonencode([
    {
      "name": "ghost_container",
      "image": "147977937220.dkr.ecr.eu-central-1.amazonaws.com/ghost:4.12.1",
      "essential": true,
      "environment": [
          { "name" : "database__client", "value" : "mysql"},
          { "name" : "database__connection__host", "value" : "${aws_db_instance.ghost.address}"},
          { "name" : "database__connection__user", "value" : "db_user"},
          { "name" : "database__connection__password", "value" : "${var.db_password}"},
          { "name" : "database__connection__database", "value" : "ghost"}
      ],
      "mountPoints": [
          {
              "containerPath": "/var/lib/ghost/content",
              "sourceVolume": "ghost_volume"
          }
      ],
      "portMappings": [
          {
          "containerPort": 2368,
          "hostPort": 2368
          }
      ],
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-create-group": "true",
                "awslogs-group": "awslogs-ghost",
                "awslogs-region": "eu-central-1",
                "awslogs-stream-prefix": "awslogs-ghost"
            }
        }
    }
  ])
}

# output "db_host" {
#   value = aws_db_instance.ghost.endpoint
# }

resource "aws_ecs_service" "ghost" {
  name            = "ghost"
  launch_type     = "FARGATE"
  cluster         = aws_ecs_cluster.ghost.id
  task_definition = aws_ecs_task_definition.task_def_ghost.arn
  desired_count   = 1
  depends_on      = [
                    aws_ecs_cluster.ghost,
                    aws_ecs_task_definition.task_def_ghost
                    ]
  load_balancer {
    target_group_arn = aws_lb_target_group.ghost-fargate.arn
    container_name   = "ghost_container"
    container_port   = 2368
  }
  network_configuration {
    subnets = [
              aws_subnet.private_a.id,
              aws_subnet.private_b.id,
              aws_subnet.private_c.id,
             ]
    security_groups = [aws_security_group.fargate_pool.id]
    assign_public_ip = false
  }

  # placement_constraints {
  #   type       = "memberOf"
  #   expression = "attribute:ecs.availability-zone in [us-north-1a, us-north-1b, us-north-1c]"
  # }
}

resource "aws_cloudwatch_dashboard" "cloudx" {
  dashboard_name = "cloudx-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
          type = "metric",
          x = 0,
          y = 0,
          width = 6,
          height = 6,
          properties = {
              metrics = [
                  [
                    "AWS/RDS",
                    "CPUUtilization",
                    "DBInstanceIdentifier",
                    "${aws_db_instance.ghost.id}"
                  ],
                  [ ".", "CPUCreditUsage", ".", "." ],
                  [ ".", "BurstBalance", ".", "." ]
              ],
          region = "eu-central-1"
          title  = "Database CPU Utilization"
          }
      },
      {
          type  = "metric",
          x     = 6,
          y     = 0,
          width = 6,
          height = 6,
          properties = {
              metrics = [
                  [
                    "AWS/RDS",
                    "DatabaseConnections",
                    "DBInstanceIdentifier",
                    "${aws_db_instance.ghost.id}"
                  ]
              ],
          region = "eu-central-1"
          title  = "Database Connections"
          }
      },
      {
          type = "metric",
          x = 12,
          y = 0,
          width = 6,
          height = 6,
          properties = {
              metrics = [
                  [
                    "AWS/RDS",
                    "ReadIOPS",
                    "DBInstanceIdentifier",
                    "${aws_db_instance.ghost.id}"
                  ],
                  [ ".", "ReadThroughput", ".", "." ]
              ]
          region = "eu-central-1"
          title  = "Database ReadIOPS"
          }
      },
      {
          type = "metric",
          x = 18,
          y = 0,
          width = 6,
          height = 6,
          properties = {
              view = "timeSeries",
              stacked = false,
              metrics = [
                  [
                    "AWS/RDS",
                    "WriteThroughput",
                    "DBInstanceIdentifier",
                    "${aws_db_instance.ghost.id}"
                  ],
                  [ ".", "WriteIOPS", ".", "." ]
              ],
          region = "eu-central-1"
          title  = "Database WriteIOPS"
         }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 9
        height = 6
        properties = {
          metrics = [
            [
              "AWS/EC2",
              "CPUUtilization",
              # "InstanceId",
              # "${aws_instance.bastion.id}"
            ]
          ]
          period = 30
          stat   = "Average"
          region = "eu-central-1"
          title  = "EC2 Instance CPU Utilization"
        }
      },
      {
          type = "metric",
          x = 9,
          y = 6,
          width = 9,
          height = 6,
          properties = {
              view = "timeSeries",
              stacked = false,
              metrics = [
                  [
                    "AWS/ECS",
                    "CPUUtilization",
                    "ServiceName", "${aws_ecs_service.ghost.name}",
                    "ClusterName", "${aws_ecs_cluster.ghost.name}"
                  ],
              ],
          stat   = "Average"
          region = "eu-central-1"
          title  = "ECS CPUUtilization"
         }
      },
      {
          type = "metric",
          x = 18,
          y = 6,
          width = 6,
          height = 6,
          properties = {
              view = "timeSeries",
              stacked = false,
              metrics = [
                  [
                    "ECS/ContainerInsights",
                    "RunningTaskCount",
                    "ServiceName", "${aws_ecs_service.ghost.name}",
                    "ClusterName", "${aws_ecs_cluster.ghost.name}"
                  ],
              ],
          region = "eu-central-1"
          title  = "ECS RunningTaskCount"
         }
      },
      {
          type = "metric"
          x = 0
          y = 12
          width = 12
          height = 6
          properties = {
              # view = "timeSeries",
              # stacked = false,
              metrics = [
                  [
                    "AWS/EFS",
                    "ClientConnections",
                    "FileSystemId",
                    "${aws_efs_file_system.ghost_content.id}"
                  ],
              ],
          stat   = "Sum"
          period = 5
          region = "eu-central-1"
          title  = "EFS ClientConnections"
         }
      },
      {
          type = "metric"
          x = 12
          y = 12
          width = 12
          height = 6
          properties = {
              metrics = [
                  [
                    "AWS/EFS",
                    "StorageBytes",
                    "FileSystemId",
                    "${aws_efs_file_system.ghost_content.id}",
                    "StorageClass", "Total",
                    { "id": "b1", "visible": false }
                  ],
                  [ { "expression": "METRICS()/1000000", "id": "m1" } ],
              ]
          yAxis = {
                  left = {
                    showUnits = false
                  }
          }
          units = "None"
          region = "eu-central-1"
          title  = "EFS StorageBytes, Mb"
         }
      }
    ]
  })
}
