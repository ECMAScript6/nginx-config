浏览器访问 mirrors，自动转向 https
server {
        listen 80;
        listen [::]:80;

        server_name mirrors.* mirror.* mirror2.* mirrors4.* mirrors6.* mirrors-i.*;
        
        if ($host ~ "mirrors\.(4|6)\.(.*)") {
                return 301 https://mirrors$1.$2$request_uri;
        }
        if ($host ~ "mirrors\.(i)\.(.*)") {
                return 301 https://mirrors-$1.$2$request_uri;
        }

        if ($http_user_agent ~ "Mozilla/5.0\ ") { 
                return 301 https://$host$request_uri;
        }
        
        location = / {
                return 301 https://$host$request_uri;
        }
        
        include /etc/nginx/conf.d/mirrors_body.confi;
}

server {
        listen 443 ssl;
        listen [::]:443 ssl;

        server_name mirrors.* mirror.* mirror2.* mirrors4.* mirrors6.* mirrors-i.*;
        
        include /etc/nginx/conf.d/mirrors_body.confi;
}
