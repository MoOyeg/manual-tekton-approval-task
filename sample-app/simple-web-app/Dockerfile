ARG BASE_IMAGE=node:latest

FROM $BASE_IMAGE

ENV SERVER_PORT=8080

MAINTAINER guray cintir guraycintir@gmail.com

WORKDIR /app

COPY . /app

RUN npm install

EXPOSE $SERVER_PORT

ENTRYPOINT [ "node", "index.js" ]