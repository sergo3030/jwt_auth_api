#!/bin/bash
# sudo yum update -y
# sudo yum install -y httpd
# sudo systemctl start httpd
# sudo systemctl enable httpd
# echo "<h1>Hello Wordld from $(hostname -f)</h1>" > /var/www/html/index.html
cd /home/ec2-user/jwt_auth_api || exit
pip-3 install -r requirements.txt
python3 app.py
