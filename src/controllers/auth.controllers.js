import { User } from "../models/user.models.js";
import { APIresponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-erroe.js";
import { asynchandler } from "../utils/async-handler.js";
import { emailVerificationContent, forgotPasswordContent, sendEmail } from "../utils/mail.js";
import jwt from "jsonwebtoken";
import { body } from "express-validator";

const generateAccessAndRefreshToken = async (userId) => {
  const user = await User.findById(userId);
  try {
    const accessToken = await user.generateAccessToken();
    const refreshToken = await user.generateRefreshToken();


    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    console.log(error);
    throw new ApiError(400, "Something went wrong while generating tokens", error);
  }
};


const registerUser = asynchandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists");
  }

  
  const user = await User.create({
    email,
    password,
    username,
    role,
    isEmailVerified: false,
  });

  
  const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });


  await sendEmail({
    email: user.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationContent(
      user.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
    ),
  });

  
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  return res
    .status(201)
    .json(
      new APIresponse(
        200,
        { user: createdUser },
        "User registered successfully. Please verify your email."
      )
    );
});


const login = asynchandler(async (req,res) => {
  console.log("hello ");
  
  const {email, password , username } = req.body;

  if(!email) {
    throw new ApiError(400,"Email is required");
  }

  const user = await User.findOne({email});

  if(!user) {
    throw new ApiError(400," User does not exist")
  }
  console.log(user);
  
console.log(password);
console.log(password);

const isPasswordValid = await user.ispasswordCorrect(password);

  if(!isPasswordValid) {
    throw new ApiError(400, "Invalid Password");  
  }

  const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)

  

const logedInUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
  );

const options = {
    httpOnly : true,
    secure : true
  }

  
  return res 
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(
        new APIresponse(
          200,
          {
            user: logedInUser,
            accessToken,
            refreshToken
          },
          "User looged In  Successsfully "
        )
      )

});


const logoutUser = asynchandler(async (req,res) => {
  console.log(req.user._id);
  
    await User.findByIdAndUpdate(
      req.user._id,
      {
        $set: {
          refreshToken: "",
        },

      },
      {
        new: true,
      },
    );

const options = {
  httpOnly: true,
  secure: true,
};

return res
      .status(200)
      .clearCookie("accessToken", options)
      .clearCookie("refreshToken", options)
      .json(new APIresponse(200, {}, "User logged out "));
});



const getCurrentUser  = asynchandler(async (req,res) => {
  return res
      .status(200)
      .json(new APIresponse(200, req.user, "Current User fetched Successfully "));
});

//  Const getcurrentUSer = asynsHandler (async (req,res) => {})

const verifyEmail = asynchandler(async (req,res) => {
  const {VerificationToken} = req.params

  if(!VerificationToken) {
    throw new ApiError(400,"Email Verification Token is missing ")
  }

let hashedToken = crypto
      .createHash("sha256")
      .update(VerificationToken)
      .digest("hex")


      await User.findOne({
        emailVerificationToken: hashedToken,
        emailVerificationExpiry: {$gt: Date.now()},
      });

      if(!User)  {
        throw new ApiError(400, "Token is invalid or expired");
      }

      User.emailVerificationToken = undefined;
      User.emailVerificationExpiry = undefined;


      User.isEmailVerified = true;
      await User.save({validateBeforeSave: false} );

      return res
        .status(200)
        .json(
          new APIresponse(
            200,
            {
              isEmailVerified: true
            }
          )
        )
});


const resendEmailVerification = asynchandler (async (req, res) => {
  const user = await User.findById(req.user?._id);

  if(!user) {
    throw new ApiError(404, "User does not exist")
  }

  if(user.isEmailVerified) {
    throw new ApiError(409, "Email is already verified")
  }

  const {unHashedToken, hashedToken, tokenExpiry} = 
        user.generateTemporaryToken();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({velidateBeforeSave: false });

  await sendEmail({
    email: User?.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationContent(
      User.username,
      `${req.protocol}: // ${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  return res
      .status(200)
      .json(
        new APIresponse(
          200,
          {},
          "Mail has been sent to your email ID"
        )
      )
});


const refreshAccessToken = asynchandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies?.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorized access");
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(decodedToken?._id);
    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }

    if (incomingRefreshToken !== user.refreshToken) {
      throw new ApiError(401, "Refresh token expired");
    }

    const options = {
      httpOnly: true,
      secure: true,
    };

    const {
      accessToken,
      refreshToken: newRefreshToken,
    } = await generateAccessAndRefreshToken(user._id);

    user.refreshToken = newRefreshToken;
    await user.save();

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new APIresponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access Token Refreshed"
        )
      );
  } catch (error) {
    throw new ApiError(401, "Invalid or expired refresh token");
  }
});


const forgotPasswordRequest = asynchandler(async (req,res) => {
  const {email} = req.body

  const user = await User.findOne({email})

  if(!user) {
    throw new ApiError(401, "User does not exist", []);
  }

  const {
    unHashedToken, hashedToken, tokenExpiry


  } = user.generateTemporaryToken()

  user.forgotPasswordToken = hashedToken
  user.forgotPasswordExpiry = tokenExpiry

  await user.save({validationBeforeSave: false})

  await sendEmail({
    email: user?.email,
    subject: "Password reset request",
    mailgenContent: forgotPasswordContent(
      user.username,
      `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unHashedToken}`,
    ),
  });

  return res
      .status(200)
      .json(
        new APIresponse(
          200,
          {},
          "Passwor reset mail has been sent on your email"
        )
      )
});


const resetForgotPassword = asynchandler(async (req,res) => {
  const {resetToken} = req.params
  const {newpassword} = req.body

  let hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex")


      const User = await User.findOne({
        forgotPasswordToken: hashedToken,
        forgotPasswordExpiry: {$gt: Date.now()}
      })

      if(!User) {
        throw new ApiError(489, "Token is invalid or expired")
      }

      User.forgotPasswordExpiry = undefined
      User.forgotPasswordToken = undefined

      User.password = newpassword;
      await User.save({velidateBeforeSave: false});

      return res
          .status(200)
          .json(new APIresponse(200, {}, "password reset  successfully"));
});


const changePassword = asynchandler(async(req,res) => {
  const {oldpassword, newpassword} = req.body
  
  const User = await User.findById(req.User?._id);

  if(!isPasswordValid) {
    throw new ApiError(400, "Invalid old Password")
  }

  User.password = newpassword
  await User.save({validateBeforeSave: false})

  return res
      .status(200)
      .json(
        new APIresponse(
          200,
          {},
          "Password Changed Successsfully "
        )
      );

});


const userChangePasswordValidator = () => {
  return [
    body("oldPassword").notEmpty().withMessage("Old Pasword is required"),
    body("newPassword").notEmpty().withMessage("New password is required"),
  ];
};


const userForgotPasswordValidator = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("Eamil is  required")
      .isEmail()
      .withMessage("Email is invalid"),
  ];
};

const userResetForgotPasswordValidator = () => {
  return [body("newPassword").notEmpty().withMessage("Password is required")];
};

export {
  registerUser,
  login,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
  forgotPasswordRequest,
  changePassword,
  resetForgotPassword,
  userResetForgotPasswordValidator ,
  userForgotPasswordValidator,
  userChangePasswordValidator,
  
  
};
