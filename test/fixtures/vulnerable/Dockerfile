FROM node:18-alpine
WORKDIR /app
COPY . .
# Misconfiguration: Explicit root user
USER root
CMD ["node", "server.js"]
