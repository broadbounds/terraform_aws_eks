#########################################################################################################################
# For our EKS cluster our VPC needs to be split into a public and private subnet in at least two Availability Zones.
# Public ones for NAT Gateways + internet-facing load balancers and private ones for worker nodes running pods.
# Our VPC and subnets has to hold specific tags: "kubernetes.io/cluster/${var.cluster_name}" = "shared" for EKS to work.
#
#########################################################################################################################


# We set AWS as the cloud platform to use
provider "aws" {
   region  = var.aws_region
   access_key = var.access_key
   secret_key = var.secret_key
 }

# We create a new VPC
resource "aws_vpc" "vpc" {
   cidr_block = var.vpc_cidr 
   instance_tenancy = "default"
   tags = {
      Name = "VPC"
      "kubernetes.io/cluster/${var.cluster_name}" = "shared"
   }
   enable_dns_hostnames = true
}

# We create a public subnet in AZ 1
# Instances will have a dynamic public IP and be accessible via the internet gateway
resource "aws_subnet" "public_subnet_1" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   cidr_block = var.public_subnet_1_CIDR
   availability_zone_id = var.AZ_1
   tags = {
      Name = "public-subnet-1"
      "kubernetes.io/cluster/${var.cluster_name}" = "shared"
   }
   map_public_ip_on_launch = true
}

# We create a public subnet in AZ 2
# Instances will have a dynamic public IP and be accessible via the internet gateway
resource "aws_subnet" "public_subnet_2" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   cidr_block = var.public_subnet_2_CIDR
   availability_zone_id = var.AZ_2
   tags = {
      Name = "public-subnet-2"
      "kubernetes.io/cluster/${var.cluster_name}" = "shared"
   }
   map_public_ip_on_launch = true
}

# We create a private subnet in AZ 1
# Instances will not be accessible via the internet gateway
resource "aws_subnet" "private_subnet_1" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   cidr_block = var.private_subnet_1_CIDR
   availability_zone_id = var.AZ_1
   tags = {
      Name = "private-subnet-1"
      "kubernetes.io/cluster/${var.cluster_name}" = "shared"
   }
}

# We create a private subnet in AZ 2
# Instances will not be accessible via the internet gateway
resource "aws_subnet" "private_subnet_2" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   cidr_block = var.private_subnet_2_CIDR
   availability_zone_id = var.AZ_2
   tags = {
      Name = "private-subnet-2"
      "kubernetes.io/cluster/${var.cluster_name}" = "shared"
   }
}

# We create an internet gateway
# Allows communication between our VPC and the internet
resource "aws_internet_gateway" "internet_gateway" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   tags = {
      Name = "internet-gateway",
   }
}

# We need 1 public routetable because it is associated to the same intenet gateway id
# We create a route table with target as our internet gateway and destination as "internet"
# Set of rules used to determine where network traffic is directed
resource "aws_route_table" "IG_route_table" {
   depends_on = [
      aws_vpc.vpc,
      aws_internet_gateway.internet_gateway,
   ]
   vpc_id = aws_vpc.vpc.id
   route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_internet_gateway.internet_gateway.id
   }
   tags = {
      Name = "IG-route-table"
   }
}

# We associate our route table to the public subnet in AZ 1
# Makes the subnet public because it has a route to the internet via our internet gateway
resource "aws_route_table_association" "associate_routetable_to_public_subnet_1" {
   depends_on = [
      aws_subnet.public_subnet_1,
      aws_route_table.IG_route_table,
   ]
   subnet_id = aws_subnet.public_subnet_1.id
   route_table_id = aws_route_table.IG_route_table.id
}

# We associate our route table to the public subnet in AZ 2
# Makes the subnet public because it has a route to the internet via our internet gateway
resource "aws_route_table_association" "associate_routetable_to_public_subnet_2" {
   depends_on = [
      aws_subnet.public_subnet_2,
      aws_route_table.IG_route_table,
   ]
   subnet_id = aws_subnet.public_subnet_2.id
   route_table_id = aws_route_table.IG_route_table.id
}

# We create an elastic IP for our NAT gateway in public subnet AZ 1
# A static public IP address that we can assign to any EC2 instance
resource "aws_eip" "elastic_ip_1" {
   vpc = true
}

# We create an elastic IP for our NAT gateway in public subnet AZ 2
# A static public IP address that we can assign to any EC2 instance
resource "aws_eip" "elastic_ip_2" {
   vpc = true
}

# We create a NAT gateway with a required public IP in public subnet AZ 1
# Lives in a public subnet and prevents externally initiated traffic to our private subnet
# Allows initiated outbound traffic to the Internet or other AWS services
resource "aws_nat_gateway" "nat_gateway_1" {
   depends_on = [
      aws_subnet.public_subnet_1,
      aws_eip.elastic_ip_1,
   ]
   allocation_id = aws_eip.elastic_ip_1.id
   subnet_id = aws_subnet.public_subnet_1.id
   tags = {
      Name = "nat-gateway-1"
   }
}

# We create a NAT gateway with a required public IP in public subnet AZ 2
# Lives in a public subnet and prevents externally initiated traffic to our private subnet
# Allows initiated outbound traffic to the Internet or other AWS services
resource "aws_nat_gateway" "nat_gateway_2" {
   depends_on = [
      aws_subnet.public_subnet_2,
      aws_eip.elastic_ip_2,
   ]
   allocation_id = aws_eip.elastic_ip_2.id
   subnet_id = aws_subnet.public_subnet_2.id
   tags = {
      Name = "nat-gateway-2"
   }
}

# We need 2 private routetables because each is associated to a specific NAT gateway id
# We create a route table with target as NAT gateway 1 and destination as "internet"
# Set of rules used to determine where network traffic is directed
resource "aws_route_table" "NAT_route_table_1" {
   depends_on = [
      aws_vpc.vpc,
      aws_nat_gateway.nat_gateway_1,
   ]
   vpc_id = aws_vpc.vpc.id
   route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_nat_gateway.nat_gateway_1.id
   }
   tags = {
      Name = "NAT-route-table-1"
   }
}

# We create a route table with target as NAT gateway 2 and destination as "internet"
# Set of rules used to determine where network traffic is directed
resource "aws_route_table" "NAT_route_table_2" {
   depends_on = [
      aws_vpc.vpc,
      aws_nat_gateway.nat_gateway_2,
   ]
   vpc_id = aws_vpc.vpc.id
   route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_nat_gateway.nat_gateway_2.id
   }
   tags = {
      Name = "NAT-route-table-2"
   }
}

# We associate our NAT route table to the private subnet 1 in AZ 1
# Keeps the subnet private because it has a route to the internet via our NAT gateway 
resource "aws_route_table_association" "associate_routetable_to_private_subnet_1" {
   depends_on = [
      aws_subnet.private_subnet_1,
      aws_route_table.NAT_route_table_1,
   ]
   subnet_id = aws_subnet.private_subnet_1.id
   route_table_id = aws_route_table.NAT_route_table_1.id
}

# We associate our NAT route table to the private subnet 2 in AZ 2
# Keeps the subnet private because it has a route to the internet via our NAT gateway
resource "aws_route_table_association" "associate_routetable_to_private_subnet_2" {
   depends_on = [
      aws_subnet.private_subnet_2,
      aws_route_table.NAT_route_table_2,
   ]
   subnet_id = aws_subnet.private_subnet_2.id
   route_table_id = aws_route_table.NAT_route_table_2.id
}

# We create a security group for SSH traffic
# EC2 instances' firewall that controls incoming and outgoing traffic
resource "aws_security_group" "sg_bastion_host" {
   depends_on = [
      aws_vpc.vpc,
   ]
   name = "sg bastion host"
   description = "bastion host security group"
   vpc_id = aws_vpc.vpc.id
   ingress {
      description = "allow ssh"
      from_port = 22
      to_port = 22
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
   }
   ingress {
      description = "allow cloudMapper"
      from_port = 8000
      to_port = 8000
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
   }
   egress {
      from_port = 0
      to_port = 0
      protocol = "-1"
      cidr_blocks = ["0.0.0.0/0"]
   }
   tags = {
      Name = "sg bastion host"
   }
}

# We create an elastic IP for our bastion host in public subnet 1 in AZ 1
# A static public IP address that we can assign to our bastion host
resource "aws_eip" "bastion_elastic_ip_1" {
   vpc = true
}

# We create an elastic IP for our bastion host in public subnet 2 in AZ 2
# A static public IP address that we can assign to our bastion host
resource "aws_eip" "bastion_elastic_ip_2" {
   vpc = true
}

# We create an ssh key using the RSA algorithm with 4096 rsa bits
# The ssh key always includes the public and the private key
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# We upload the public key of our created ssh key to AWS
resource "aws_key_pair" "public_ssh_key" {
  key_name   = var.public_key_name
  public_key = tls_private_key.ssh_key.public_key_openssh

   depends_on = [tls_private_key.ssh_key]
}

# We save our public key at our specified path.
# Can upload on remote server for ssh encryption
resource "local_file" "save_public_key" {
  content = tls_private_key.ssh_key.public_key_openssh 
  filename = "${var.key_path}${var.public_key_name}.pem"
}

# We save our private key at our specified path.
# Allows private key instead of a password to securely access our instances
resource "local_file" "save_private_key" {
  content = tls_private_key.ssh_key.private_key_pem
  filename = "${var.key_path}${var.private_key_name}.pem"
}

# We create a bastion host in public subnet 1 in AZ 1
# Allows SSH into instances in private subnet
resource "aws_instance" "bastion_host_1" {
   depends_on = [
      aws_security_group.sg_bastion_host,
   ]
   ami = var.ec2_ami
   instance_type = var.ec2_type
   key_name = aws_key_pair.public_ssh_key.key_name
   vpc_security_group_ids = [aws_security_group.sg_bastion_host.id]
   subnet_id = aws_subnet.public_subnet_1.id
   tags = {
      Name = "bastion host 1"
   }
   provisioner "file" {
    source      = "${var.key_path}${var.private_key_name}.pem"
    destination = "/home/ec2-user/private_ssh_key.pem"
    connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.ssh_key.private_key_pem
    host     = aws_instance.bastion_host_1.public_ip
    }
  }
}

# We create a bastion host in public subnet 2 in AZ 2
# Allows SSH into instances in private subnet
resource "aws_instance" "bastion_host_2" {
   depends_on = [
      aws_security_group.sg_bastion_host,
   ]
   ami = var.ec2_ami
   instance_type = var.ec2_type
   key_name = aws_key_pair.public_ssh_key.key_name
   vpc_security_group_ids = [aws_security_group.sg_bastion_host.id]
   subnet_id = aws_subnet.public_subnet_2.id
   tags = {
      Name = "bastion host 2"
   }
   provisioner "file" {
    source      = "${var.key_path}${var.private_key_name}.pem"
    destination = "/home/ec2-user/private_ssh_key.pem"
    connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.ssh_key.private_key_pem
    host     = aws_instance.bastion_host_2.public_ip
    }
  }
}

# We associate the elastic ip to our bastion host 1
resource "aws_eip_association" "bastion_eip_association_1" {
  instance_id   = "${aws_instance.bastion_host_1.id}"
  allocation_id = "${aws_eip.bastion_elastic_ip_1.id}"
}

# We associate the elastic ip to our bastion host 2
resource "aws_eip_association" "bastion_eip_association_2" {
  instance_id   = "${aws_instance.bastion_host_2.id}"
  allocation_id = "${aws_eip.bastion_elastic_ip_2.id}"
}

# We create a security group for our application load balancer
# EC2 instances' firewall that controls incoming and outgoing traffic
resource "aws_security_group" "sg_load_balancer" {
  name        = "security group load balancer"
  description = "Allow all inbound traffic"
  vpc_id     = "${aws_vpc.vpc.id}"
 # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
   
 # HTTPS access from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }   
 # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "sg-load-balancer"
  }
  depends_on = [
    aws_vpc.vpc
  ]
}

# We create a target group for our application load balancer
resource "aws_alb_target_group" "tg_load_balancer" {
  name     = "target-group-load-balancer"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id
  depends_on = [
    aws_vpc.vpc
  ]
}

# We create our application load balancer
resource "aws_alb" "load_balancer" {
  name               = "load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.sg_load_balancer.id]
  subnets            = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]
  enable_deletion_protection = false
  tags = {
    Environment = "production"
  }
  depends_on = [
    aws_security_group.sg_load_balancer,
    aws_subnet.public_subnet_1,
    aws_subnet.public_subnet_2
  ]
}

# We create a listener for our application load balancer
resource "aws_alb_listener" "listener_load_balancer" {
  load_balancer_arn = aws_alb.load_balancer.id
  port              = "80"
  protocol          = "HTTP"
  default_action {
    target_group_arn = aws_alb_target_group.tg_load_balancer.id
    type             = "forward"
  }
  depends_on = [
    aws_alb.load_balancer,
    aws_alb_target_group.tg_load_balancer
  ]
}

# We create a security group for our wordpress instance
resource "aws_security_group" "security_group_wordpress" {
  depends_on = [
    aws_vpc.vpc,
  ]
  name        = "security-group-wordpress"
  description = "Allow http inbound traffic"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    description = "allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.public_subnet_1_CIDR, var.public_subnet_2_CIDR]   
  }
   
  ingress {
    description = "allow HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.public_subnet_1_CIDR, var.public_subnet_2_CIDR]
  }
   
  ingress {
    description = "allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${aws_eip.bastion_elastic_ip_1.public_ip}/32", "${aws_eip.bastion_elastic_ip_2.public_ip}/32"] 
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_launch_configuration" "wordpress_instance" {
  name_prefix   = "wordpress-instance-"
  image_id      = var.ec2_ami
  instance_type = var.ec2_type
  key_name      = aws_key_pair.public_ssh_key.key_name
  security_groups = [aws_security_group.security_group_wordpress.id]
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    aws_security_group.security_group_wordpress
  ]
}

resource "aws_autoscaling_group" "auto_scaling_wordpress_az_1" {
  name                 = "auto-scaling-wordpress-az-1"
  launch_configuration = aws_launch_configuration.wordpress_instance.name
  min_size             = 2
  max_size             = 6
  vpc_zone_identifier       = [aws_subnet.private_subnet_1.id]
  target_group_arns         = [aws_alb_target_group.tg_load_balancer.id]
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    aws_launch_configuration.wordpress_instance,
    aws_subnet.private_subnet_1,
    aws_alb_target_group.tg_load_balancer
  ]
}

resource "aws_autoscaling_group" "auto_scaling_wordpress_az_2" {
  name                 = "auto-scaling-wordpress-az-2"
  launch_configuration = aws_launch_configuration.wordpress_instance.name
  min_size             = 2
  max_size             = 6
  vpc_zone_identifier       = [aws_subnet.private_subnet_2.id]
  target_group_arns         = [aws_alb_target_group.tg_load_balancer.id]
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    aws_launch_configuration.wordpress_instance,
    aws_subnet.private_subnet_2,
    aws_alb_target_group.tg_load_balancer
  ]
}


################################################################################################################################
# EKS requires that we set an IAM role for the cluster control plane that holds enough permission to write to CloudWatch Logs 
# (for control plane components logging) and other policies like creating and tagging EC2 resources (for managed worker nodes).
# AWS has two managed policy to attach to create this IAM role easily: arn:aws:iam::aws:policy/AmazonEKSServicePolicy and 
# arn:aws:iam::aws:policy/AmazonEKSClusterPolicy.
#
###############################################################################################################################

# Here we create the role for Amazon EKS 
resource "aws_iam_role" "eks_cluster" { 
  name = "${var.cluster_name}_role"

  # The cluster-role-trust-policy.json 
  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

# Here we attach the required Amazon EKS managed IAM policy to the role
# Amazon EKS needs this policy to create AWS resources for Kubernetes clusters
resource "aws_iam_role_policy_attachment" "policy-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

# Amazon EKS needs this policy to manage network interfaces, their private IP addresses
# and their attachment and detachment to and from instances
resource "aws_iam_role_policy_attachment" "policy-AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_cluster.name
}

# To log control plane components
resource "aws_cloudwatch_log_group" "eks_cluster_control_plane_components" { 
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = 7
}




#########################################################################################################################
# 
#
#########################################################################################################################

# Here we create the EKS cluster itself.
resource "aws_eks_cluster" "cluster" { 
  name = var.cluster_name 
  # The cluster needs an IAM role to gain some permission over your AWS account 
  role_arn = aws_iam_role.eks_cluster.arn 

  vpc_config {
    # We pass all our subnets (public and private ones)
    subnet_ids = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id, aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]
    # The cluster will have a public endpoint. We will be able to call it from the public internet to interact with it
    endpoint_public_access = true 
    # The cluster will have a private endpoint too. Worker nodes will be able to call the control plane without leaving the VPC
    endpoint_private_access = true   
  }

  # We enable control plane components logging against Amazon Cloudwatch log group
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"] 

  # Ensure that IAM Role permissions are handled before the EKS Cluster
  depends_on = [
    aws_iam_role_policy_attachment.policy-AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.policy-AmazonEKSVPCResourceController,
    aws_cloudwatch_log_group.eks_cluster_control_plane_components
  ]
}



#########################################################################################################################
# We must configure our computer to communicate with our cluster
# For that, we must create a kubeconfig file for our cluster.
# The settings in this file enable the kubectl CLI to communicate with our cluster.
# We can automatically create our kubeconfig file with the AWS CLI
# By default, the config file is created in ~/.kube/config
#########################################################################################################################

# We generate a kubeconfig (needs aws cli >=1.62 and kubectl)
resource "null_resource" "generate_kubeconfig" { 

  # NB: eks will not work until the aws --version command shows you any version less than 1.15.32 because EKS was introduced with version 1.15.32
  # To upgrading the awscli version 
  # yum install python3-pip 
  # pip3 install --upgrade --user awscli
  # aws --version 
  provisioner "local-exec" {
    command = "aws eks update-kubeconfig --name ${var.cluster_name}"
  }

  depends_on = [aws_eks_cluster.cluster]
}




#########################################################################################################################
# When using Amazon EKS, you need to authenticate against Amazon IAM prior to call your Kubernetes cluster. 
# Each kubectl call will first authenticate against AWS IAM to retrieve a token, and then, will hit the EKS cluster. 
# Missing this authentication step will result in all your kubectl call ending up with a 401 response. 
# That token can be retrieved by calling aws eks get-token, and we can add some configurations to the kubeconfig to call this command every time.
#########################################################################################################################


