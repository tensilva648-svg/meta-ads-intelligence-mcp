FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY tsconfig.json ./
COPY src ./src
EXPOSE 8787
CMD ["npm","start"]
