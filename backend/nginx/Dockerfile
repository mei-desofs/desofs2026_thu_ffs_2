FROM nginx:alpine

# Install openssl to generate self-signed certificate for local development
RUN apk add --no-cache openssl

# Create SSL directory
RUN mkdir -p /etc/nginx/ssl

# Generate a self-signed certificate valid for 365 days
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/key.pem \
    -out /etc/nginx/ssl/cert.pem \
    -subj "/C=PT/ST=Porto/L=Porto/O=Kryptos/OU=Dev/CN=localhost"

# Copy the custom NGINX configuration
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
