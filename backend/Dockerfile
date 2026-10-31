FROM node:20-alpine
WORKDIR /app
COPY backend/package.json ./backend/package.json
RUN cd backend && npm install --omit=dev
COPY migrations ./migrations
COPY backend ./backend
WORKDIR /app/backend
RUN mkdir -p storage/audio && chown -R node:node /app
USER node
EXPOSE 4000
CMD ["node", "src/server.js"]
