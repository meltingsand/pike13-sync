# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodeuser -u 1001

# Copy application code
COPY --chown=nodeuser:nodejs . .

# Switch to non-root user
USER nodeuser

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "
    const http = require('http');
    const options = { hostname: 'localhost', port: 3000, path: '/health', timeout: 2000 };
    const req = http.request(options, (res) => { process.exit(res.statusCode === 200 ? 0 : 1); });
    req.on('error', () => process.exit(1));
    req.end();
  "

# Start application
ENTRYPOINT ["dumb-init", "--"]
CMD ["npm", "start"]
