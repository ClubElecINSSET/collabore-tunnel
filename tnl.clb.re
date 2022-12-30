map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

server {
    server_name ~^(?<app_name>.+)\.tnl.clb.re$;
    listen 80;

    #listen 443 ssl;

    #ssl_certificate /etc/nginx/ssl/certs/tnl.clb.re.pem;
    #ssl_certificate_key /etc/nginx/ssl/certs/tnl.clb.re.key;

    error_page 502 /notunnel.txt;
    location = /notunnel.txt {
                return 200 "No tunnel available.";
                internal;
    }

    location / {
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_pass http://unix:/tmp/collabore-tunnel/${app_name}.sock;
    }

    server_tokens off;
}

server {
    server_name tnl.clb.re
    listen 80;

    #listen 443 ssl;

    #ssl_certificate /etc/nginx/ssl/certs/tnl.clb.re.pem;
    #ssl_certificate_key /etc/nginx/ssl/certs/tnl.clb.re.key;

    location / {
        return 302 https://tunnel.collabore.fr/;
    }

    server_tokens off;
}
