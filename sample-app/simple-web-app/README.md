Sample web app forked from https://github.com/gcintir/simple-web-app.git

# simple-web-app
Simple Web Application with Node.js and Express


## Requirements
* Node.js

## Setup

```bash
cd simple-web-app
npm install
node index.js
```

## GET Request for testing
http://localhost:8081/


## Dockerize Application
```bash
docker build . -t nodejs_express_image:latest
docker run -d --rm -p 8085:8085 -e SERVER_PORT=8085 nodejs_express_image:latest
docker logs <container_id>
docker kill <container_id>
```



