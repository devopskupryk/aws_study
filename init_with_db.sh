#!/bin/bash -xe

exec > >(tee /var/log/cloud-init-output.log|logger -t user-data -s 2>/dev/console) 2>&1
### Update this to match your ALB DNS name
LB_DNS_NAME='cloudx-alb-1526312250.eu-central-1.elb.amazonaws.com'
###
DB_USER=db_user
DB_NAME=ghost
SSM_DB_PASSWORD="/ghost/dbpassw"

REGION=$(/usr/bin/curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/[a-z]$//')
EFS_ID=$(aws efs describe-file-systems --query 'FileSystems[?Name==`ghost_content`].FileSystemId' --region $REGION --output text)
DB_PASSWORD=$(aws ssm get-parameter --name $SSM_DB_PASSWORD --query Parameter.Value --with-decryption --region $REGION --output text)
DB_URL=$(aws rds describe-db-instances --query 'DBInstances[?DBName==`ghost`].Endpoint.Address' --region $REGION --output text)

### Install pre-reqs
curl -sL https://rpm.nodesource.com/setup_14.x | sudo bash -
yum install -y nodejs amazon-efs-utils
npm install ghost-cli@latest -g

adduser ghost_user
usermod -aG wheel ghost_user
cd /home/ghost_user/

sudo -u ghost_user ghost install [4.12.1] local

### EFS mount
mkdir -p /home/ghost_user/ghost/content/data
mount -t efs -o tls $EFS_ID:/ /home/ghost_user/ghost/content

cat << EOF > config.development.json

{
  "url": "http://${LB_DNS_NAME}",
  "server": {
    "port": 2368,
    "host": "0.0.0.0"
  },
  "database": {
    "client": "mysql",
    "connection": {
        "host": "$DB_URL",
        "port": 3306,
        "user": "$DB_USER",
        "password": "$DB_PASSWORD",
        "database": "$DB_NAME"
    }
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": [
      "file",
      "stdout"
    ]
  },
  "process": "local",
  "paths": {
    "contentPath": "/home/ghost_user/content"
  }
}
EOF

sudo -u ghost_user ghost stop
sudo -u ghost_user ghost start
