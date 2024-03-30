FROM openresty/openresty:1.25.3.1-2-alpine-fat-aarch64

RUN /usr/local/openresty/luajit/bin/luarocks install lua-resty-jwt

ENV JWT_SECRET=secret

COPY nginx.conf /nginx.conf
COPY bearer.lua /bearer.lua

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;", "-c", "/nginx.conf"]