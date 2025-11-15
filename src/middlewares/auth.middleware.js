import {User} from "../models/user.models.js";
import { ApiError } from "../utils/api-erroe.js";
import { asynchandler } from "../utils/async-handler.js";
import jwt from "jsonwebtoken";

export const verifyJWT = asynchandler(async(req,res,next) =>{
    const token = req.cookies?.accessToken || req.header
    ("Authrization")?.replace("Bearer","")

    if(!token){
        throw new ApiError(401,"Unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)

        const  user = await User.findById(decodedToken?._id).
        select("-password -refreshToken -emailVerificationToken -emailVerificationExpiry")
        if(!user) throw new ApiError(404, "User not found!");
        req.user = user;
        next();
    } catch (error) {
        console.log(error);
        
    }
})