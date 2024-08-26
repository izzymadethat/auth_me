const jwt = require("jsonwebtoken");
const { jwtConfig } = require("../config");
const { User } = require("../db/models");

const { secret, expiresIn } = jwtConfig;

/**
 * Sets the JWT cookie after the user is logged in or signed up
 * @param {Response} res
 * @param {User} user
 * @returns string
 */
const setTokenCookie = (res, user) => {
  // Creates the token
  const safeUser = {
    id: user.id,
    email: user.email,
    username: user.username,
  };

  const token = jwt.sign({ data: safeUser }, secret, {
    expiresIn: parseInt(expiresIn), // Set to 604,800, or 1 week
  });

  const isProduction = process.env.NODE_ENV === "production";

  //   set the token cookie
  res.cookie("token", token, {
    maxAge: expiresIn * 1000,
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction && "Lax",
  });

  return token;
};

/**
 * Middleware that restores a user's session based on the token in the cookies
 * @param {Request} req
 * @param {Response} res
 * @param {Function} next
 * @returns Function
 */
const restoreUser = (req, res, next) => {
  // token parsed from cookies
  const { token } = req.cookies;
  req.user = null;

  return jwt.verify(token, secret, null, async (err, jwtPayload) => {
    if (err) {
      return next();
    }

    try {
      const { id } = jwtPayload.data;
      req.user = await User.findByPk(id, {
        attributes: {
          include: ["email", "createdAt", "updatedAt"],
        },
      });
    } catch (e) {
      res.clearCookie("token");
      return next();
    }

    if (!req.user) res.clearCookie("token");

    return next();
  });
};

/**
 * Middleware that ensures valid JWT cookie exists. If there is no session user, then it will pass the request to error-handling middleware
 * @param {Request} req
 * @param {Response} res
 * @param {Function} next
 * @returns Function
 */
const requireAuth = (req, res, next) => {
  if (req.user) return next();

  const err = new Error("Authentication required");
  err.title = "Authentication required";
  err.errors = { message: "Authentication required" };
  err.status = 401;
  return next(err);
};

module.exports = { setTokenCookie, restoreUser, requireAuth };
