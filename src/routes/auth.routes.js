import { Router  } from "express"; 
import { registerUser,login, logoutUser, verifyEmail, refreshAccessToken, forgotPasswordRequest, resetForgotPassword, getCurrentUser, userResetForgotPasswordValidator, changePassword, resendEmailVerification } from "../controllers/auth.controllers.js";

import { validate } from "../middlewares/validator.middleware.js";
import {userRegisterValidator , userLoginValidator} from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

// Unsecured Routes

router.route("/register").post(userRegisterValidator(), validate,registerUser);

router.route("/login").post(userLoginValidator(), validate, login);

router.route("/verify-email/:verficationToken").get(verifyEmail);

router.route("/refresh-token").post(refreshAccessToken);
router.route("/forgot-password").post(forgotPasswordRequest);

router.route("/reset-password/:resetToken").post(userResetForgotPasswordValidator(), validate, resetForgotPassword);

// Secure or Proctected Routes  
router.route("/logout").post(verifyJWT,logoutUser);
router.route("/current-user").post(verifyJWT, getCurrentUser);
router.route("/change-password").post(verifyJWT,changePassword);
router.route("/resend-email-verification").post(verifyJWT, resendEmailVerification);

export default router;

