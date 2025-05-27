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