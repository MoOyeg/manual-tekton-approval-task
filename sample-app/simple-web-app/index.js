var express = require('express');

var app = express();

const PORT = process.env.SERVER_PORT;
const MESSAGE = process.env.MESSAGE;

app.get('/', function (req, res) {
  res.send(MESSAGE);
});

app.listen(PORT, function () {
    console.log('Simple Web Application running on port ' + PORT);
});