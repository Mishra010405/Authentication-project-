import dotenv from "dotenv";
import app from "./app.js"
import connectdb from "./db/index.js";

// import express from "express";


dotenv.config({
  path: "./.env",
});

// let myusername = process.env.value;
// console.log("value:", myusername);
// console.log("database is:", process.env.database);
// console.log("Start of an awesome project the of the backend");

// const app = express();
const port = process.env.PORT || 3000;

// to keep short the code..

// app.get("/", (req, res) => {
//   res.send("HELLO World");
// });

// app.get("/instagram", (req, res) => {
//   res.send("This is the instagram page");
// });

// app.listen(port, () => {
//   console.log(`Examples are listening on the port http://localhost:${port}`);
// });


connectdb() 
    .then(() => {
        app.listen(port,() => {
            console.log(`Examples are listening on the port http://localhost:${port}`);
        });
    } )
    .catch((err) => {
        console.log("🔯 Mongodb connection error", err);
        process.exit(1);
    })


