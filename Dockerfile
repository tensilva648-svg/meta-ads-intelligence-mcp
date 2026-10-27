FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN RUN npm install
COPY tsconfig.json ./
COPY src ./src
EXPOSE 8787
CMD ["npm","start"]
