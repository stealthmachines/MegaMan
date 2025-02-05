#!/bin/bash
set -e

echo "[+] Updating system and installing dependencies..."
apt update && apt upgrade -y
apt install -y curl nginx openssl unbound tor avahi-daemon avahi-utils jq iptables-persistent

# Ensure directories exist
mkdir -p /etc/dnsmasq.d /etc/tor /etc/nginx/sites-available /etc/nginx/ssl /etc/unbound/unbound.conf.d /var/lib/unbound

# Install Pi-hole if not already installed
if ! command -v pihole &> /dev/null; then
    echo "[+] Installing Pi-hole..."
    curl -sSL https://install.pi-hole.net | sudo PIHOLE_SKIP_OS_CHECK=true bash
fi

# Configure Unbound
echo "[+] Configuring Unbound..."
cat > /etc/unbound/unbound.conf <<EOL
server:
    interface: 127.0.0.1
    interface: ::1
    access-control: 127.0.0.1 allow
    access-control: ::1 allow
    port: 5335  # Using non-standard port to avoid conflict
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    hide-identity: yes
    hide-version: yes
    forward-zone:
        name: "."
        forward-addr: 127.0.0.1@9053
EOL

# Add DNSSEC validation to Unbound
echo "[+] Adding DNSSEC validation to Unbound..."
cat > /etc/unbound/unbound.conf.d/pi-hole.conf <<EOL
server:
    verbosity: 1
    interface: 0.0.0.0
    port: 5353  # Changed from default to prevent conflicts
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    access-control: 0.0.0.0/0 allow
    access-control: ::0/0 allow
    cache-max-ttl: 86400
    cache-min-ttl: 3600
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    prefetch: yes
    num-threads: 2
    so-reuseport: yes
    msg-cache-size: 128m
    rrset-cache-size: 256m
    infra-cache-numhosts: 100000
    infra-cache-lame-size: 10k
    neg-cache-size: 4m
    do-not-query-localhost: no
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    harden-glue: yes
    harden-below-nxdomain: yes
    target-fetch-policy: "2 1 0 0 0"
    val-log-level: 1
    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
EOL

# Configure Pi-hole
echo "[+] Configuring Pi-hole..."
cat > /etc/dnsmasq.d/02-custom.conf <<EOL
server=127.0.0.1#5353  # Pointing to Unbound's new port
server=::1#5353
no-resolv
EOL

# Configure Tor Hidden Service
echo "[+] Configuring Tor Hidden Service..."
mkdir -p /var/lib/tor/pihole
chown -R debian-tor:debian-tor /var/lib/tor/pihole
chmod 700 /var/lib/tor/pihole
cat > /etc/tor/torrc <<EOL
HiddenServiceDir /var/lib/tor/pihole/
HiddenServicePort 53 127.0.0.1:5354  # Changed to avoid conflict
HiddenServicePort 80 127.0.0.1:80
HiddenServicePort 9053 127.0.0.1:9053
AutomapHostsOnResolve 1
DNSPort 127.0.0.1:9053
TransPort 9041  # Changed from 9040 to avoid conflict
SocksPort 127.0.0.1:9050
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsSuffixes .onion,.exit
TransListenAddress 0.0.0.0
DNSListenAddress 0.0.0.0
EOL

echo "[+] Restarting Tor..."
systemctl restart tor

# Enable Avahi for local discovery
echo "[+] Enabling Avahi for local discovery..."
systemctl enable avahi-daemon
systemctl restart avahi-daemon

echo "[+] Waiting for Tor Hidden Service to be available..."
sleep 20
ONION_ADDR=$(cat /var/lib/tor/pihole/hostname)

echo "[+] Registering local and remote peers..."
PEER_FILE="/etc/pihole/nodes.conf"
avahi-browse -rt _pihole._tcp | grep "=" | awk '{print $6}' > $PEER_FILE
echo "tor://$ONION_ADDR" >> $PEER_FILE

while read -r NODE; do
    echo "Discovered node: $NODE"
    curl -s "http://$NODE/peers" >> $PEER_FILE || true
done < $PEER_FILE

echo "[+] Updating Unbound configuration..."
UNBOUND_CONF="/etc/unbound/unbound.conf"
sed -i 's/do-not-query-localhost: yes/do-not-query-localhost: no/g' $UNBOUND_CONF
sed -i '/forward-zone:/,/^$/d' $UNBOUND_CONF
cat >> $UNBOUND_CONF <<EOL
forward-zone:
    name: "."
    forward-addr: 127.0.0.1@9053
EOL

echo "[+] Restarting Unbound..."
systemctl restart unbound

# Generate SSL certificate
echo "[+] Generating self-signed SSL certificate..."
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    -keyout /etc/nginx/ssl/nginx-selfsigned.key \
    -out /etc/nginx/ssl/nginx-selfsigned.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Configure NGINX
echo "[+] Configuring NGINX with SSL to redirect to Pi-hole..."
cat > /etc/nginx/sites-available/default <<EOL
server {
    listen 444 ssl;  # Changed from 443 to avoid conflict with common HTTPS
    server_name localhost;

    ssl_certificate /etc/nginx/ssl/nginx-selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx-selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        return 302 https://$host/admin/;
    }
}

server {
    listen 80;
    server_name localhost;
    return 301 https://\$host\$request_uri;
}
EOL

ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

echo "[+] Installing iptables-persistent..."
apt install -y iptables-persistent

echo "[+] Configuring iptables to force all traffic through Tor..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner debian-tor -j ACCEPT
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 9053
iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 9053
iptables -t nat -A OUTPUT -d 127.0.0.1 -j RETURN
iptables -t nat -A OUTPUT -d 192.168.0.0/16 -j RETURN
iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9041  # Changed to match torrc
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -j REJECT

iptables-save > /etc/iptables.rules

echo "[+] Saving iptables rules..."
netfilter-persistent save
netfilter-persistent reload
systemctl enable netfilter-persistent

# Delay restarts to fix potential race conditions
echo "[+] Delaying service restarts..."
sleep 10

echo "[+] Restarting services..."
systemctl restart pihole-FTL
systemctl restart unbound
systemctl restart nginx

echo "[+] Setup completed with Pi-hole, Unbound, Tor, iptables, and SSL configured!"
