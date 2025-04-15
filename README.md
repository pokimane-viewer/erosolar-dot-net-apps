# erosolar-dot-net from fresh elastic compute engine, installing nginx to reverse proxy visitors who visit on external http/s IPs on / to port 3000 localhost, which next.js serves by running nodejs.

# Update system
sudo apt update && sudo apt upgrade -y

# Install Nginx
sudo apt install nginx -y

# Configure Nginx to proxy requests on erosolar.net to port 3000
sudo tee /etc/nginx/sites-available/erosolar.net > /dev/null <<'EOF'
server {
    listen 80;
    server_name erosolar.net www.erosolar.net;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF

# Enable the config
sudo ln -s /etc/nginx/sites-available/erosolar.net /etc/nginx/sites-enabled/

# Test and reload Nginx
sudo nginx -t && sudo systemctl reload nginx

# Install Certbot and the Nginx plugin
sudo apt install certbot python3-certbot-nginx -y

# Obtain and install the SSL certificate
sudo certbot --nginx -d erosolar.net -d www.erosolar.net --non-interactive --agree-tos -m admin@erosolar.net --redirect

# Auto-renewal cron job (optional - usually added by Certbot)
sudo systemctl enable certbot.timer

# restart nginx

sudo systemctl restart nginx
 
# erosolar.net/encryption
gunicorn --bind 0.0.0.0:5000 encryption:app &


 # erosolar.net/circuits
gunicorn --bind 0.0.0.0:6969 circuits:app &

# to kill and restart gunicorn (or anything else)

ps aux | grep "gunicorn"

sudo kill -9 pid of whatever the fuck you wanna kill

# pyinstaller for the desktop pgp applications

python3.12 -m PyInstaller desktop_pgp.py

# screenshot demos

![image](https://github.com/user-attachments/assets/5fee10cb-138e-4f69-b1d0-4550725d9832)

![image](https://github.com/user-attachments/assets/d3cf70d5-ae03-48a4-bedc-29ac190e16ba)

This is full ECC (all 3 types) it's not demos but i have to edit it manually to reflect this

![image](https://github.com/user-attachments/assets/45f199bd-6ddb-40ff-8f6d-fa539c68e423)

![image](https://github.com/user-attachments/assets/705c4a03-e9dd-4957-90eb-fffe21b497f7)

This is diffie demo but i have to edit manually; ChatGPT can make mistakes...

![image](https://github.com/user-attachments/assets/b87364a3-92a3-411a-86c4-53c346b2eed5)


![image](https://github.com/user-attachments/assets/8db0180f-53b4-4c21-8a36-4a1b72c9857a)

![image](https://github.com/user-attachments/assets/838ca501-1f58-413e-a173-9c36370aa8bb)

![image](https://github.com/user-attachments/assets/40147576-c04c-48f1-8486-94f706bbfc6f)
