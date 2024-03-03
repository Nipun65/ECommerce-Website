const express = require("express");
const router = express.Router();
const { check, body } = require("express-validator");
const User = require("../models/user");
const bcrypt = require("bcryptjs");
const {
  getLogInPage,
  postLogin,
  postLogout,
  getSignUpPage,
  postSignup,
  getReset,
  postReset,
  getNewPassword,
  postNewPassword,
} = require("../controllers/auth");

router.get("/login", getLogInPage);
router.post(
  "/login",
  [
    check("email")
      .isEmail()
      .withMessage("Please enter a valid email")
      .custom((value, { req }) => {
        return User.findOne({ email: value }).then((userDoc) => {
          if (!userDoc) {
            return Promise.reject("E-mail does not exist");
          }
        });
      })
      .normalizeEmail(),
    body("password", "Password has to be valid.")
      .isLength({ min: 5 })
      .isAlphanumeric()
      .trim(),
  ],
  postLogin
);
router.get("/signup", getSignUpPage);
router.post(
  "/signup",
  [
    check("email")
      .isEmail()
      .withMessage("Please enter a valid email")
      .custom((value, { req }) => {
        // if (value === 'test@gmail.com') {
        //   throw new Error('This email is forbidden');
        // }
        // return true;

        return User.findOne({ email: value }).then((userDoc) => {
          if (userDoc) {
            return Promise.reject(
              "E-mail exists already, please pick a different one."
            );
          }
        });
      }),
    body(
      "password",
      "Please Enter a password with only numbers and text and atleast 5 characters."
    )
      .isLength({ min: 5 })
      .isAlphanumeric(),
    body("confirmpassword").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Password have to match");
      }
      return true;
    }),
  ],
  postSignup
);
router.post("/login", postLogin);
router.post("/logout", postLogout);
router.get("/reset-password", getReset);
router.post("/reset-password", postReset);
router.get("/reset-password/:token", getNewPassword);
router.post("/new-password", postNewPassword);

module.exports = router;
