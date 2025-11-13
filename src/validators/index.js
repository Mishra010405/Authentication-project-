import { body } from "express-validator";


export const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),

    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .isLowercase()        
      .withMessage("Username must be in lowercase")
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long"),

    body("password") 
      .trim()
      .notEmpty()
      .withMessage("Password is required"),

    body("fullName") 
      .optional()
      .trim(),
  ];
};


export const userLoginValidator = () => {
  return [
    body("email")
      .optional()
      .isEmail()
      .withMessage("Email is invalid"),

    body("password") // lowercase to match frontend form
      .notEmpty()
      .withMessage("Password is required"),
  ];
};
