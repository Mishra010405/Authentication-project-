import { User } from "../models/user.models.js";
import { APIresponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-erroe.js";
import { asynchandler } from "../utils/async-handler.js";
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js";


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

export { registerUser , login};
