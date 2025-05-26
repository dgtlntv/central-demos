# Use Node.js LTS version for building
FROM node:24-alpine as builder

# Set working directory
WORKDIR /app

# Install git to clone the repository
RUN apk add --no-cache git

# Clone the MAAS UI repository
RUN git clone https://github.com/canonical/maas-ui.git .

# Install dependencies and build the application
# The cleanbuild command runs: yarn clean-all && yarn build
RUN yarn cleanbuild

# Production stage - serve with nginx
FROM nginx:alpine

# Copy the built application from builder stage to the correct path
COPY --from=builder /app/build /usr/share/nginx/html/MAAS/r

# Create nginx configuration for SPA routing and base path
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