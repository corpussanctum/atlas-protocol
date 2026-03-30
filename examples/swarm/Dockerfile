FROM node:20-slim

WORKDIR /app

# Install deps (production + tsx for live TS execution)
COPY package*.json ./
RUN npm ci --include=optional

# Global tsx so we can run directly
RUN npm install -g tsx

COPY . .

# Default command runs the full simulated swarm
CMD ["npx", "tsx", "examples/swarm/run-swarm.ts"]
