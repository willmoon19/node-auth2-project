const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs')
const User = require('../users/users-model')
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body
  const { role_name } = req
  const hash = bcrypt.hashSync(password, 8)
  User.add({ username, password: hash, role_name })
  .then(data => {
    res.status(201).json(data)
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
  if (bcrypt.compareSync(req.body.pasword, req.user.password)) {
    const token = buildToken(req.user)
    res.json({
      "message": `${req.user.username} is back!`,
      token,
    })
  } else {
    next({
      status: 401,
      message: 'sup'
    })
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

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    role_name: user.role_name,
    username: user.username,
  }
  const options = {
    expiresIn:'2d',
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
