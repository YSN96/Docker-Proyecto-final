const bodyParser = require("body-parser");
const express = require("express");
const cors = require("cors");
const app = express();
const conn = require("express-myconnection");
const models = require("./db/db");
const mysql = require("mysql2");

const controllerApi = require("./api/controllerApi.js");
const createApi = require("./api/createApi.js");


app.use(bodyParser.urlencoded({ extended: false }));



app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({limit: "50mb", extended: true, parameterLimit:50000}));
app.use(cors());

app.all("*", function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, Content-Length, Authorization, Accept, X-Requested-With , yourHeaderFeild"
  );
  res.header("Access-Control-Allow-Methods", "PUT,POST,GET,DELETE,OPTIONS");
  res.header("X-Powered-By", " 3.2.1");
  res.header("Content-Type", "application/json;charset=utf-8");
  next();
});

app.use(conn(mysql, models.mysql, "single"));
app.use("/api",controllerApi);
app.use("/api/createApi", createApi);
app.listen(8000);
console.log("success");
