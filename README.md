# wantasticd
wantastic custom userspace wireguard client daemon

# Installation
## Linux
No prerequisites required.
```
wget https://github.com/wantastic/wantasticd/releases/download/${VERSION}/wantasticd-linux-${ARCH}
chmod +x wantasticd-linux-${ARCH}
sudo mv wantasticd-linux-${ARCH} /usr/local/bin/wantasticd
```
## connect
To connect to a WireGuard server, use the `connect` command.
```
wantasticd connect -config /etc/wireguard/wg0.conf
```
## status
To check the status of the WireGuard connection, use the `status` command.
```
wantasticd status
```
## login
To login to the WireGuard server, use the `login` command.
```
wantasticd login -token ${TOKEN}
```
## login with browser
To login to the WireGuard server with a browser, use the `login` command without any flags.
```
wantasticd login
```
