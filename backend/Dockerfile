FROM node:latest

WORKDIR /var/www/app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 8000
CMD [ "node", "app.js" ]
