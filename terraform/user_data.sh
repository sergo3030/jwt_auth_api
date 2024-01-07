#!/bin/bash
cd /home/ec2-user/jwt_auth_api || exit
sudo pip-3 install -r requirements.txt
sudo python3 app.py
