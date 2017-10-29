测试测试
下面的是一键安装nginx 1.10.3 最新稳定版本，编译参数是官方推荐的。

yum groupinstall "Development Tools"   -y
yum  install wget   zlib-devel openssl-devel pcre-devel -y
cd /usr/local/src
wget http://nginx.org/download/nginx-1.10.3.tar.gz
tar zxvf nginx-1.10.3.tar.gz
cd nginx-1.10.3
groupadd -g 58 nginx
useradd -u 58 -g 58 -M nginx -s /sbin/nologin
mkdir -p /var/tmp/nginx/{client,proxy,fastcgi,uwsgi,scgi}
mkdir -p /var/cache/nginx/client_temp
./configure \
--user=nginx --group=nginx \
--prefix=/etc/nginx   \
--sbin-path=/usr/sbin/nginx \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--pid-path=/var/run/nginx.pid \
--lock-path=/var/run/nginx.lock \
--http-client-body-temp-path=/var/cache/nginx/client_temp \
--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
--user=nginx \
--group=nginx \
--with-http_ssl_module \
--with-http_realip_module \
--with-http_addition_module \
--with-http_sub_module \
--with-http_dav_module \
--with-http_flv_module \
--with-http_mp4_module \
--with-http_gunzip_module \
--with-http_gzip_static_module \
--with-http_random_index_module \
--with-http_secure_link_module \
--with-http_stub_status_module \
--with-http_auth_request_module \
--with-threads \
--with-stream \
--with-stream_ssl_module \
--with-http_slice_module \
--with-mail \
--with-mail_ssl_module \
--with-file-aio \
--with-http_v2_module \
--with-ipv6
make && make install
nginx -V
  
  
Centos7 启动方式

cat  >> /lib/systemd/system/nginx.service  <<EOF
[Unit]
Description=nginx - high performance web server
Documentation=http://nginx.org/en/docs/
After=network.target remote-fs.target nss-lookup.target
   
[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -c /etc/nginx/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true
   
[Install]
WantedBy=multi-user.target
EOF



systemctl enable nginx.service
systemctl start  nginx.service
netstat -lntup  | grep 80




内核优化  

cat   >>  /etc/sysctl.conf << EOF
net.ipv4.ip_forward = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
kernel.sysrq = 0
kernel.core_uses_pid = 1
net.ipv4.tcp_syncookies = 1
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rmem = 4096        87380   4194304
net.ipv4.tcp_wmem = 4096        16384   4194304
net.core.wmem_default = 8388608
net.core.rmem_default = 8388608
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 262144
net.core.somaxconn = 262144
net.ipv4.tcp_max_orphans = 3276800
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_mem = 94500000 915000000 927000000
net.ipv4.tcp_fin_timeout = 1
net.ipv4.tcp_keepalive_time = 30
net.ipv4.ip_local_port_range = 1024    6500
EOF





sysctl -p
cd /etc/nginx/
mv nginx.conf nginx.conf.bak





配置文件优化，启用HTTPS

vim nginx.conf
user  nginx nginx;
worker_processes  auto;
worker_rlimit_nofile 65535;

error_log  /var/log/nginx/error.log  info;
pid        /var/run/nginx.pid;

events {
    use epoll;
    worker_connections 10240;
    multi_accept on;
}

http
    {
    include       mime.types;
    default_type  application/octet-stream;

    charset  utf-8;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    server_names_hash_bucket_size 128;
    client_header_buffer_size 16k;
    large_client_header_buffers 4 16k;
    client_max_body_size 50m;

    server_tokens off;
    autoindex off;

    sendfile on;
    tcp_nopush     on;

    keepalive_timeout 60;
    tcp_nodelay  on;
    client_header_timeout 15;
    reset_timedout_connection on;
    client_body_timeout 15;
    send_timeout 15;

   
     
    fastcgi_intercept_errors on;

    fastcgi_connect_timeout 300;
    fastcgi_send_timeout 300;
    fastcgi_read_timeout 300;
    fastcgi_buffer_size 16k;
    fastcgi_buffers 16 16k;
    fastcgi_busy_buffers_size 16k;
    fastcgi_temp_file_write_size 16k;

    fastcgi_cache_path /etc/nginx/fastcgi_cache levels=1:2
                    keys_zone=TEST:10m
                    inactive=5m;

    fastcgi_cache TEST;
    fastcgi_cache_valid 200 302 1h;
    fastcgi_cache_valid 301 1d;
    fastcgi_cache_valid any 1m;
    fastcgi_cache_min_uses 1;
    fastcgi_cache_use_stale error timeout invalid_header http_500;
    fastcgi_cache_key "$request_method://$host$request_uri";

    open_file_cache max=204800 inactive=20s;
    open_file_cache_min_uses 1;
    open_file_cache_valid 30s;

    gzip on;
    gzip_min_length  1k;
    gzip_buffers     4 16k;
    gzip_http_version 1.1;
    gzip_comp_level 5;
    gzip_types       text/css application/javascript  text/xml;
    gzip_vary on;
    gzip_disable "MSIE [1-6].(?!.*SV1)";


    server
        {
        listen       80;
        server_name  hequan.lol;
        index index.php index.html  index.htm;
        root html;

        return         301 https://$server_name$request_uri;

    }

    server {
        listen 443  ssl;
        server_name hequan.lol;
        index index.html index.htm index.php default.html default.htm default.php;

        root  html;

        ssl on;
        ssl_certificate      /etc/nginx/key/1_www.hequan.lol_bundle.crt;
        ssl_certificate_key  /etc/nginx/key/2_www.hequan.lol.key;

        ssl_ciphers "EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5";
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;

        location /status
            {
            stub_status on;
            access_log off;
            #allow 127.0.0.1;
            #deny all;
        }

        error_page  400 401 402 403 404  /40x.html;
        location = /40x.html {
                root  html;
                index  index.html index.htm;
        }

        error_page  500 501 502 503 504  /50x.html;
        location = /50x.html {
            root  html;
            index  index.html index.htm;
        }

         
        location ~ \.php$ {
            root           html;
            fastcgi_pass   127.0.0.1:9000;
            fastcgi_index  index.php;
            fastcgi_param  SCRIPT_FILENAME  /etc/nginx/html$fastcgi_script_name;
            include        fastcgi_params;
        }

        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
            {
            expires 30d;
        }

        location ~ .*\.(js|css)?$
            {
            expires 12h;
        }
    }
}



日志切割

cat >> log.sh <<EOF
#!/bin/bash
path=/var/log/nginx/backup
if [ ! -d  "#path"  ]; then
    mkdir -p $path
fi
cd  /var/log/nginx
mv access.log   backup/$(date +%F -d -1day).log
systemctl reload  nginx.service
EOF


crontab -e
00 00 * * * /var/log/nginx/log.sh  > /dev/null 2&1





#############################################################
 nginx配置ssl加密（单/双向认证、部分https）
seanlook 2016-05-18 14:59:57 浏览2939 评论0

nginx HTTPS ssl证书

摘要： nginx下配置ssl本来是很简单的，无论是去认证中心买SSL安全证书还是自签署证书，但最近公司OA的一个需求，得以有个机会实际折腾一番。一开始采用的是全站加密，所有访问http:80的请求强制转换（rewrite）到https，后来自动化测试结果说响应速度太慢，https比http慢慢30倍，心想怎么可能，鬼知道他们怎么测的。

nginx下配置ssl本来是很简单的，无论是去认证中心买SSL安全证书还是自签署证书，但最近公司OA的一个需求，得以有个机会实际折腾一番。一开始采用的是全站加密，所有访问http:80的请求强制转换（rewrite）到https，后来自动化测试结果说响应速度太慢，https比http慢慢30倍，心想怎么可能，鬼知道他们怎么测的。所以就试了一下部分页面https（不能只针对某类动态请求才加密）和双向认证。下面分节介绍。

默认nginx是没有安装ssl模块的，需要编译安装nginx时加入--with-http_ssl_module选项。

关于SSL/TLS原理请参考 这里，如果你只是想测试或者自签发ssl证书，参考 这里 。

提示：nignx到后端服务器由于一般是内网，所以不加密。
1. 全站ssl

全站做ssl是最常见的一个使用场景，默认端口443，而且一般是单向认证。

server {
        listen 443;
        server_name example.com;

        root /apps/www;
        index index.html index.htm;

        ssl on;
        ssl_certificate ../SSL/ittest.pem;
        ssl_certificate_key ../SSL/ittest.key;

#        ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
#        ssl_ciphers ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP;
#        ssl_prefer_server_ciphers on;

}

如果想把http的请求强制转到https的话：

server {
  listen      80;
  server_name example.me;
  rewrite     ^   https://$server_name$request_uri? permanent;

### 使用return的效率会更高 
#  return 301 https://$server_name$request_uri;
}

ssl_certificate证书其实是个公钥，它会被发送到连接服务器的每个客户端，ssl_certificate_key私钥是用来解密的，所以它的权限要得到保护但nginx的主进程能够读取。当然私钥和证书可以放在一个证书文件中，这种方式也只有公钥证书才发送到client。

ssl_protocols指令用于启动特定的加密协议，nginx在1.1.13和1.0.12版本后默认是ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2，TLSv1.1与TLSv1.2要确保OpenSSL >= 1.0.1 ，SSLv3 现在还有很多地方在用但有不少被攻击的漏洞。

ssl_ciphers选择加密套件，不同的浏览器所支持的套件（和顺序）可能会不同。这里指定的是OpenSSL库能够识别的写法，你可以通过 openssl -v cipher 'RC4:HIGH:!aNULL:!MD5'（后面是你所指定的套件加密算法） 来看所支持算法。

ssl_prefer_server_ciphers on设置协商加密算法时，优先使用我们服务端的加密套件，而不是客户端浏览器的加密套件。
https优化参数

    ssl_session_cache shared:SSL:10m; : 设置ssl/tls会话缓存的类型和大小。如果设置了这个参数一般是shared，buildin可能会参数内存碎片，默认是none，和off差不多，停用缓存。如shared:SSL:10m表示我所有的nginx工作进程共享ssl会话缓存，官网介绍说1M可以存放约4000个sessions。 详细参考serverfault上的问答ssl_session_cache。
    ssl_session_timeout ： 客户端可以重用会话缓存中ssl参数的过期时间，内网系统默认5分钟太短了，可以设成30m即30分钟甚至4h。

设置较长的keepalive_timeout也可以减少请求ssl会话协商的开销，但同时得考虑线程的并发数了。

提示：在生成证书请求csr文件时，如果输入了密码，nginx每次启动时都会提示输入这个密码，可以使用私钥来生成解密后的key来代替，效果是一样的，达到免密码重启的效果：

openssl rsa -in ittest.key -out ittest_unsecure.key

导入证书

如果你是找一个知名的ssl证书颁发机构如VeriSign、Wosign、StartSSL签发的证书，浏览器已经内置并信任了这些根证书，如果你是自建C或获得二级CA授权，都需要将CA证书添加到浏览器，这样在访问站点时才不会显示不安全连接。各个浏览的添加方法不在本文探讨范围内。
2. 部分页面ssl

一个站点并不是所有信息都是非常机密的，如网上商城，一般的商品浏览可以不通过https，而用户登录以及支付的时候就强制经过https传输，这样用户访问速度和安全性都得到兼顾。

但是请注意不要理解错了，是对页面加密而不能针对某个请求加密，一个页面或地址栏的URL一般会发起许多请求的，包括css/png/js等静态文件和动态的java或php请求，所以要加密的内容包含页面内的其它资源文件，否则就会出现http与https内容混合的问题。在http页面混有https内容时，页面排版不会发生乱排现象；在https页面中包含以http方式引入的图片、js等资源时，浏览器为了安全起见会阻止加载。

下面是只对example.com/account/login登录页面进行加密的栗子：

root /apps/www;
index index.html index.htm;

server {
    listen      80;
    server_name example.com;

    location ^~ /account/login {
        rewrite ^ https://$server_name:443$request_uri? permanent;
    }
    location / {
        proxy_pass  http://localhost:8080;

        ### Set headers ####
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_redirect     off; 
    }
}

server {
    listen 443 ssl;
    server_name example.com;

    ssl on;
    ssl_certificate ../SSL/ittest.pem;
    ssl_certificate_key ../SSL/ittest.key;
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP;
    ssl_prefer_server_ciphers on;

    location ^~ /account/login {
        proxy_pass  http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_redirect     off; 

        ### Most PHP, Python, Rails, Java App can use this header -> https ###
        proxy_set_header X-Forwarded-Proto  $scheme;
    }
    location / {
        rewrite  ^  http://$server_name$request_uri? permanent;
    }
}

关于rewrite与location的写法参考这里。当浏览器访问http://example.com/account/login.xx时，被301到https://example.com/account/login.xx，在这个ssl加密的虚拟主机里也匹配到/account/login，反向代理到后端服务器，后面的传输过程是没有https的。这个login.xx页面下的其它资源也是经过https请求nginx的，登录成功后跳转到首页时的链接使用http，这个可能需要开发代码里面控制。

    上面配置中使用了proxy_set_header X-Forwarded-Proto $scheme，在jsp页面使用request.getScheme()得到的是https 。如果不把请求的$scheme协议设置在header里，后端jsp页面会一直认为是http，将导致响应异常。
    ssl配置块还有个与不加密的80端口类似的location /，它的作用是当用户直接通过https访问首页时，自动跳转到不加密端口，你可以去掉它允许用户这样做。

3. 实现双向ssl认证

上面的两种配置都是去认证被访问的站点域名是否真实可信，并对传输过程加密，但服务器端并没有认证客户端是否可信。（实际上除非特别重要的场景，也没必要去认证访问者，除非像银行U盾这样的情况）

要实现双向认证HTTPS，nginx服务器上必须导入CA证书（根证书/中间级证书），因为现在是由服务器端通过CA去验证客户端的信息。还有必须在申请服务器证书的同时，用同样的方法生成客户证书。取得客户证书后，还要将它转换成浏览器识别的格式（大部分浏览器都认识PKCS12格式）：

openssl pkcs12 -export -clcerts -in client.crt -inkey client.key -out client.p12

然后把这个client.p12发给你相信的人，让它导入到浏览器中，访问站点建立连接的时候nginx会要求客户端把这个证书发给自己验证，如果没有这个证书就拒绝访问。

同时别忘了在 nginx.conf 里配置信任的CA：（如果是二级CA，请把根CA放在后面，形成CA证书链）

    proxy_ignore_client_abort on；

    ssl on;
    ...
    ssl_verify_client on;
    ssl_verify_depth 2;
    ssl_client_certificate ../SSL/ca-chain.pem;

#在双向location下加入：
    proxy_set_header X-SSL-Client-Cert $ssl_client_cert;

拓展：使用geo模块

nginx默认安装了一个ngx_http_geo_module，这个geo模块可以根据客户端IP来创建变量的值，用在如来自172.29.73.0/24段的IP访问login时使用双向认证，其它段使用一般的单向认证。

geo $duplexing_user {
    default 1;
    include geo.conf;  # 注意在0.6.7版本以后，include是相对于nginx.conf所在目录而言的
}

语法 geo [$address] $variable { … }，位于http段，默认地址是$reoute_addr，假设 conf/geo.conf 内容：

127.0.0.1/32    LOCAL;  # 本地
172.29.73.23/32 SEAN;   # 某个IP
172.29.73.0/24  1;      # IP段，可以按国家或地域定义后面的不同的值

需要配置另外一个虚拟主机server{ssl 445}，里面使用上面双向认证的写法，然后在80或443里使用变量$duplexing_user去判断，如果为1就rewrite到445，否则rewrite到443。具体用法可以参考nginx geo使用方法。

####################################################################

#user  nobody;
worker_processes  auto;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;


events {

    worker_connections  8000;

}


http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  20s;
    server_tokens off;

  fastcgi_connect_timeout 300;
  fastcgi_send_timeout 300;
  fastcgi_read_timeout 300;
  fastcgi_buffer_size 16k;
  fastcgi_buffers 4 16k;
  fastcgi_busy_buffers_size 16k;
  fastcgi_temp_file_write_size 16k;

    #gzip  on;

  gzip on;
  gzip_min_length  256;
  gzip_buffers     4 32k;
  gzip_http_version 1.1;
  gzip_comp_level 5;
  #gzip_types       text/plain application/x-javascript text/css application/xml;
    gzip_types
    application/atom+xml
    application/javascript
    application/json
    application/ld+json
    application/manifest+json
    application/rss+xml
    application/vnd.geo+json
    application/vnd.ms-fontobject
    application/x-font-ttf
    application/x-web-app-manifest+json
    application/xhtml+xml
    application/xml
    font/opentype
    image/bmp
    image/svg+xml
    image/x-icon
    text/cache-manifest
    text/css
    text/plain
    text/vcard
    text/vnd.rim.location.xloc
    text/vtt
    text/x-component
    text/x-cross-domain-policy;
  gzip_vary on;
  gzip_disable "MSIE [1-6].";

  server_names_hash_bucket_size 128;
  client_max_body_size     100m; 
  client_header_buffer_size 256k;
  large_client_header_buffers 4 256k;

  limit_conn_zone $binary_remote_addr zone=TotalConnLimitZone:10m ;
  limit_conn  TotalConnLimitZone  50;
  limit_conn_log_level notice;

  limit_req_zone $binary_remote_addr zone=ConnLimitZone:10m  rate=10r/s;
  limit_req_log_level notice;

	server {
   listen 80;
   server_name www.jingzheng.com jingzheng.com;

   location / {
      root "C:\phpStudy\WWW";
      index index.php index.html;

      # Nginx找不到文件时，转发请求给后端Apache
      error_page 404 @proxy;

      # css, js 静态文件设置有效期1天
      location ~ .*\.(js|css)$ {
         access_log off;
         expires      1d;
      }

      # 图片设置有效期3天
      location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$ {
         access_log off;
         expires      3d;
      }
   }

	location ~ /\.ht {
	deny  all;
	}
	location ~ /\. {
	deny  all;
	}

   # 动态文件.php请求转发给后端Apache
   location ~ \.php$ {
     #proxy_redirect off;
     #proxy_pass_header Set-Cookie;
     #proxy_set_header Cookie $http_cookie;

      # 传递真实IP到后端
      proxy_set_header Host $http_host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

      proxy_pass   http://127.0.0.1:8080;
   }

   location @proxy {
      proxy_set_header Host $http_host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

      proxy_pass http://127.0.0.1:8080;
   }
}

	server{ 
	listen 80 default; 
	server_name _; 
	return 444; 
	}

    #server {
        #listen	80;
        #server_name	www.jingzheng.com;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        #location / {
        #    root	"C:\phpStudy\WWW";
        #    index  index.html index.htm index.php;
	#    try_files $uri $uri/ /index.php$is_args$args;#这里后面的 $is_args$args是为了获取URL参数的，不获取可省略
        #}

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        #error_page   500 502 503 504  /50x.html;
        #location = /50x.html {
        #    root   "C:\phpStudy\WWW";
        #}

        # proxy the PHP scripts to Apache listening on 127.0.0.1:80
        #
        #location ~ \.php$ {
        #    proxy_pass   http://127.0.0.1;
        #}

        # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
        #
        #location ~ \.php$ {
        #    root	"C:\phpStudy\WWW";
         #   fastcgi_pass	127.0.0.1:9000;
        #    fastcgi_index	index.php;
	    
	#    limit_req zone=ConnLimitZone burst=5 nodelay;
	#    try_files $uri =404;#这里加入这一行，防止出错的 页面被PHP解析
        #fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
	# fastcgi_param  SCRIPT_FILENAME C:\phpStudy\WWW$fastcgi_script_name;
        # include	fastcgi_params;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #    deny  all;
        #}
    #}


    # another virtual host using mix of IP-, name-, and port-based configuration
    #
    #server {
    #    listen       8000;
    #    listen       somename:8080;
    #    server_name  somename  alias  another.alias;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}
    ####################ssl#######################
	server {
	    listen 443;
	    server_name www.jingzheng.com;
	    ssl on;
	    root html;
	    index index.html index.htm;
	    ssl_certificate   "213980615740170.pem";
	    ssl_certificate_key  "213980615740170.key";
	    ssl_session_timeout 5m;
	    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
	    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
	    ssl_prefer_server_ciphers on;
	    #location / {
		#root html;
		#index index.html index.htm;
	   # }
		       location / {
	      root "C:\phpStudy\WWW";
	      index index.php index.html;

	      # Nginx找不到文件时，转发请求给后端Apache
	      error_page 404 @proxy;

	      # css, js 静态文件设置有效期1天
	      location ~ .*\.(js|css)$ {
		 access_log off;
		 expires      1d;
	      }

	      # 图片设置有效期3天
	      location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$ {
		 access_log off;
		 expires      3d;
	      }
	   }

		location ~ /\.ht {
		deny  all;
		}
		location ~ /\. {
		deny  all;
		}

	   # 动态文件.php请求转发给后端Apache
	   location ~ \.php$ {
	     #proxy_redirect off;
	     #proxy_pass_header Set-Cookie;
	     #proxy_set_header Cookie $http_cookie;

	      # 传递真实IP到后端
	      proxy_set_header Host $http_host;
	      proxy_set_header X-Real-IP $remote_addr;
	      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

	      proxy_pass   http://127.0.0.1:8080;
	   }

	   location @proxy {
	      proxy_set_header Host $http_host;
	      proxy_set_header X-Real-IP $remote_addr;
	      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

	      proxy_pass http://127.0.0.1:8080;
	   }
	}

    # HTTPS server
    #
    #server {
    #    listen       443 ssl;
    #    server_name  localhost;

    #    ssl_certificate      cert.pem;
    #    ssl_certificate_key  cert.key;

    #    ssl_session_cache    shared:SSL:1m;
    #    ssl_session_timeout  5m;

    #    ssl_ciphers  HIGH:!aNULL:!MD5;
    #    ssl_prefer_server_ciphers  on;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}

}
