# Art3mis
External Pentesting tool with web Facing GUI
# Clone or upload the artemis folder to /tmp/artemis then:
cd /tmp/artemis
sudo bash install.sh

# install.sh now handles everything: installs all tools, deploys files to /opt/artemis/, installs and starts the systemd service, and creates /opt/artemis/results/ for scan output.

# From your local machine — open an SSH tunnel:
ssh -L 5000:localhost:5000 root@YOUR-LINODE-IP

# Then open in your browser, the service binds to 127.0.0.1:5000 only — it is never exposed on a public port. The SSH tunnel is the only way in.
http://localhost:5000


# Useful service commands on the Linode
systemctl status artemis       # check it's running
systemctl restart artemis      # restart after code changes
journalctl -fu artemis         # live logs from the service


# After a scan completes, click ↺ NEW SCAN in the footer. This calls /api/reset, clears all state server-side, wipes the log panel, and returns the form to its blank state — ready for the next engagement without any page reload or server restart needed.

-----------------------------------
# Setting it up externally
Nginx as a reverse proxy with HTTP Basic Auth — Nginx sits in front of Flask, handles HTTPS (via Let's Encrypt), and requires a username/password before anyone reaches the app. Flask stays on localhost:5000, Nginx handles the public-facing port 443.

# 1. Install Nginx and Certbot on your Linode
sudo apt install nginx certbot python3-certbot-nginx -y

2. Create the Basic Auth password file
sudo apt install apache2-utils -y
sudo htpasswd -c /etc/nginx/.artemis_passwd yourusername
# Enter a strong password when prompted

# 3. Nginx config — create /etc/nginx/sites-available/artemis
```
server {
    listen 80;
    server_name YOUR-LINODE-IP-OR-DOMAIN;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name YOUR-LINODE-IP-OR-DOMAIN;

    ssl_certificate     /etc/letsencrypt/live/YOUR-DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/YOUR-DOMAIN/privkey.pem;

    # Basic auth gate
    auth_basic           "Artemis — Authorized Access Only";
    auth_basic_user_file /etc/nginx/.artemis_passwd;

    # SSE requires buffering off
    proxy_buffering    off;
    proxy_cache        off;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        # Required for Server-Sent Events to stream correctly
        proxy_http_version 1.1;
        proxy_set_header   Connection '';
        chunked_transfer_encoding on;
    }
}
```
# Enable It
```
sudo ln -s /etc/nginx/sites-available/artemis /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

# Get TLS cert if you have a domain pointed at your VM
```
sudo certbot --nginx -d yourdomain.com
```


