#!/bin/bash
sudo -u ec2-user -i <<'EOF'

pip-3 install -r /home/ec2-user/jwt_auth_api/requirements.txt
python3 /home/ec2-user/jwt_auth_api/app.py &

EOF