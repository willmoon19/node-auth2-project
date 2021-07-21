const router = require("express").Router();
const bcrypt = require('bcryptjs');
const tokenBuilder = require('./token-builder')
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
// const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require('../users/users-model')

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body
  const { role_name } = req
  const hash = bcrypt.hashSync(password, 8)
  User.add({ username, password: hash, role_name })
    .then(user => {
      res.status(201).json(user)
    })
    .catch(next)

  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  if(bcrypt.compareSync(req.body.password, req.user.password)){
    const token = tokenBuilder(req.user)
    res.status(200).json({
      message: `${req.user.username} is back!`,
      token,
    })
  } else {
    next({status: 401, message: "problems"})
  }

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
