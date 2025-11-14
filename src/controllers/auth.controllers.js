import { User } from "../models/user.models.js";
import { APIresponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-erroe.js";
import { asynchandler } from "../utils/async-handler.js";
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js";
import jwt from "jsonwebtoken";

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
    mailgenContent: emailVerificationMailgenContent(
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
  const User = await User.findById(req.user?._id);

  if(!User) {
    throw new ApiError(404, "User does not exist")
  }

  if(email.isEmailVerified) {
    throw new ApiError(409, "Email is already verified")
  }

  const {unHashedToken, hashedToken, tokenExpiry} = 
        User.generateTemporaryToken();

  User.emailVerificationToken = hashedToken;
  User.emailVerificationExpiry = tokenExpiry;

  await User.save({velidateBeforeSave: false });

  await sendEmail({
    email: User?.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
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

export {
  registerUser,
  login,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
};
