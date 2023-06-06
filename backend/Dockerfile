FROM node:latest

WORKDIR /var/www/app

COPY package*.json ./

RUN npm install
# If you are building your code for production
# RUN npm ci --omit=dev

COPY . .

EXPOSE 8000
CMD [ "node", "app.js" ]
