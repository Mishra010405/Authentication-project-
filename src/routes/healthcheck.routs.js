import { Router } from "express";
import { healthcheck } from "../controllers/healthcheck.controler.js";

const router  = Router();

router.route("/healthcheck").get(healthcheck);

export default router;