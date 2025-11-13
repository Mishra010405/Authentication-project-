import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";


const app = express();

// Basic Configuration
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
// Cookie Parser
app.use(cookieParser());

// CORS Configuration
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || ["http://localhost:5173"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// import the routes

import healthcheckrouter from "./routes/healthcheck.routs.js";
import authRouter from "./routes/auth.routes.js";

app.use("/api/v1/healthcheck", healthcheckrouter);
app.use("/api/v1/auth", authRouter)

app.use("/api/v1", healthcheckrouter);
// app.use("/instaram",healthcheckrouter)


// Routes
app.get("/", (req, res) => {
  res.send("Welcome to the basecampy");
});

export default app;




