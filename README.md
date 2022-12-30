
<h2 align="center">collabore tunnel</h2>
<p align="center">Make your local services accessible to all on the public Internet</p>
<p align="center">
    <a href="#about">About</a> •
    <a href="#features">Features</a> •
    <a href="#usage">Usage</a> •
    <a href="#demo">Demo</a> •
    <a href="#deploy">Deploy</a> •
    <a href="#configuration">Configuration</a> •
    <a href="#license">License</a>
</p>

## About

collabore tunnel is a free and open source service offered as part of the [club elec collabore platform](https://collabore.fr) operated by [club elec](https://clubelec.insset.fr) that allows you to expose your local services on the public Internet.  
Showing your friends or colleagues your work on your next website (for example) has never been easier!

collabore tunnel works with two software parts:

- A SSH server developed in Python that allows clients to connect to it and expose their local services to the public Internet by creating a tunnel between the client and the server. The server transmits traffic between the public Internet and the remote local service via a UNIX domain socket on the server.
- A NGINX web server that makes available on the public Internet the service that has been forwarded with a subdomain based on the UNIX socket name.

## Features

- ✅ **Easy** to use
- ✅ **No download** and **no signup**
- ✅ Use the **SSH client** already installed on your device
- ✅ Generates a random **link** that **can be shared with anyone**
- ✅ **TLS** and **non-TLS** terminaisons
- ✅ **Compatible** with any protocol

## Usage

```
ssh -R /:host:port ssh.tunnel.collabore.fr
```

## Demo

```
 $ ssh -R /:localhost:8000 ssh.tunnel.collabore.fr
===============================================================================
Welcome to collabore tunnel!
collabore tunnel is a free and open source service offered as part of the
club elec collabore platform (https://collabore.fr) operated by club elec that
allows you to expose your local services on the public Internet.
To learn more about collabore tunnel,
visit the documentation website: https://tunnel.collabore.fr/
club elec (https://clubelec.insset.fr) is a french not-for-profit
student organisation.
===============================================================================

Your local service has been exposed to the public Internet address: hivs5g9l739ywr2n.tnl.clb.re
TLS termination: https://hivs5g9l739ywr2n.tnl.clb.re
```

## Deploy

We have deployed collabore tunnel on a server running Ubuntu Server 22.04.

**Please adapt these steps to your configuration, ...**  
*We do not describe the usual server configuration steps or how to link a domain to a server.*

### Install required packages

```
apt install python3-pip nginx
```

### Retrieve sources

```
mkdir /opt/collabore-tunnel
```

```
cd /opt/collabore-tunnel
```

```
git clone https://github.com/ClubElecINSSET/collabore-tunnel .
```

### Install Python dependencies

```
pip install -r requirements.txt
```

### Install NGINX virtualhosts

```
rm /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
```

```
cp tnl.clb.re ssh.tunnel.collabore.fr /etc/nginx/sites-available/
```

```
ln -s /etc/nginx/sites-available/tnl.clb.re /etc/nginx/sites-enabled/tnl.clb.re
```

```
ln -s /etc/nginx/sites-available/ssh.tunnel.collabore.fr /etc/nginx/sites-enabled/ssh.tunnel.collabore.fr
```

### Install systemd service

```
cp collabore-tunnel.service /etc/systemd/system/
```

### Install Let's Encrypt certificate

#### Install acme.sh

```
curl https://get.acme.sh | sh -s email=clubelec.insset@gmail.com
```

#### Edit the acme.sh account configuration file

Create access to the OVH API by [clicking here](https://api.ovh.com/createToken/?GET=/domain/zone/clb.re/*&POST=/domain/zone/clb.re/*&PUT=/domain/zone/clb.re/*&GET=/domain/zone/clb.re&DELETE=/domain/zone/clb.re/record/*).  
This is necessary for the generation of a wildcard certificate.

```
nano /root/.acme.sh/account.conf 
```

And add at the end of the file:

```
SAVED_OVH_AK='application key'
SAVED_OVH_AS='application secret'
SAVED_OVH_CK='consumer key'
```

#### Generate certificates

```
/root/.acme.sh/acme.sh --issue --keylength 4096 -d tnl.clb.re -d '*.tnl.clb.re' --dns dns_ovh --server letsencrypt
```

```
/root/.acme.sh/acme.sh --issue --keylength 4096 -d ssh.tunnel.collabore.fr --nginx --server letsencrypt
```

#### Install certificates

```
mkdir -p /etc/nginx/ssl/certs
```

```
/root/.acme.sh/acme.sh --install-cert -d tnl.clb.re -d '*.tnl.clb.re' --key-file /etc/nginx/ssl/certs/tnl.clb.re.key --fullchain-file /etc/nginx/ssl/certs/tnl.clb.re.pem --reloadcmd "service nginx force-reload"
```

```
/root/.acme.sh/acme.sh --install-cert -d ssh.tunnel.collabore.fr --key-file /etc/nginx/ssl/certs/ssh.tunnel.collabore.fr.key --fullchain-file /etc/nginx/ssl/certs/ssh.tunnel.collabore.fr.pem --reloadcmd "service nginx force-reload"
```

### Edit and reload NGINX configuration

Please remove the #'s in the files `/etc/nginx/sites-available/tnl.clb.re` and `/etc/nginx/sites-available/ssh.tunnel.collabore.fr`.

```
systemctl reload nginx
```

### Enable and start systemd service

```
systemctl enable collabore-tunnel
```

```
systemctl start collabore-tunnel
```

## Configuration

To configure the collabore tunnel, please modify the configurations of the NGINX virtualhosts and the systemd service according to your needs.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see http://www.gnu.org/licenses/.