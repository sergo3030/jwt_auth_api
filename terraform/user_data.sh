#!/bin/bash
sudo -u ec2-user -i <<'EOF'

cd /home/ec2-user/jwt_auth_api/
python3 app.py &

EOF