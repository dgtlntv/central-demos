ARG MAAS_URL=http://10.48.119.165:5240/

FROM node:24-alpine as builder

WORKDIR /app

RUN apk add --no-cache git

RUN git clone https://github.com/canonical/maas-ui.git .

ENV MAAS_URL=${MAAS_URL}

RUN yarn cleanbuild

FROM nginx:alpine

COPY --from=builder /app/build /usr/share/nginx/html/MAAS/r

ENV MAAS_URL=${MAAS_URL}

RUN echo 'server { \
    listen 80; \
    server_name localhost; \
    root /usr/share/nginx/html; \
    index index.html; \
    \
    # Proxy API endpoints to MAAS backend \
    location /MAAS/api/ { \
        proxy_pass ${MAAS_URL}; \
        proxy_set_header Host $host; \
        proxy_set_header X-Real-IP $remote_addr; \
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; \
        proxy_set_header X-Forwarded-Proto $scheme; \
        proxy_set_header Origin ${MAAS_URL}; \
        proxy_set_header Referer ${MAAS_URL}$request_uri; \
        proxy_redirect off; \
    } \
    \
    location /MAAS/accounts/ { \
        proxy_pass ${MAAS_URL}; \
        proxy_set_header Host $host; \
        proxy_set_header X-Real-IP $remote_addr; \
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; \
        proxy_set_header X-Forwarded-Proto $scheme; \
        proxy_set_header Origin ${MAAS_URL}; \
        proxy_set_header Referer ${MAAS_URL}$request_uri; \
        proxy_redirect off; \
    } \
    \
    location /MAAS/a/ { \
        proxy_pass ${MAAS_URL}; \
        proxy_set_header Host $host; \
        proxy_set_header X-Real-IP $remote_addr; \
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; \
        proxy_set_header X-Forwarded-Proto $scheme; \
        proxy_set_header Origin ${MAAS_URL}; \
        proxy_set_header Referer ${MAAS_URL}$request_uri; \
        proxy_redirect off; \
    } \
    \
    location /MAAS/docs/ { \
        proxy_pass ${MAAS_URL}; \
        proxy_set_header Host $host; \
        proxy_set_header X-Real-IP $remote_addr; \
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; \
        proxy_set_header X-Forwarded-Proto $scheme; \
        proxy_set_header Origin ${MAAS_URL}; \
        proxy_set_header Referer ${MAAS_URL}$request_uri; \
        proxy_redirect off; \
    } \
    \
    # Proxy WebSocket endpoint \
    location /MAAS/ws/ { \
        proxy_pass ${MAAS_URL}; \
        proxy_http_version 1.1; \
        proxy_set_header Upgrade $http_upgrade; \
        proxy_set_header Connection "upgrade"; \
        proxy_set_header Host $host; \
        proxy_set_header X-Real-IP $remote_addr; \
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; \
        proxy_set_header X-Forwarded-Proto $scheme; \
        proxy_set_header Origin ${MAAS_URL}; \
        proxy_set_header Referer ${MAAS_URL}$request_uri; \
        proxy_cache_bypass $http_upgrade; \
        proxy_read_timeout 86400; \
    } \
    \
    # Handle the base path /MAAS/r/ \
    location /MAAS/r/ { \
        try_files $uri $uri/ /MAAS/r/index.html; \
    } \
    \
    # Redirect root to the base path (preserve port) \
    location = / { \
        return 301 $scheme://$http_host/MAAS/r/; \
    } \
    \
    # Redirect MAAS base to the UI \
    location = /MAAS { \
        return 301 $scheme://$http_host/MAAS/r/; \
    } \
    \
    location = /MAAS/ { \
        return 301 $scheme://$http_host/MAAS/r/; \
    } \
    \
    # Handle static assets anywhere \
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ { \
        expires 1y; \
        add_header Cache-Control "public, immutable"; \
    } \
}' > /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

# Start nginx
CMD ["nginx", "-g", "daemon off;"]