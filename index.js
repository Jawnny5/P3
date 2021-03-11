const express = require('express')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const app = express()
const port = process.env.PORT || 9000

const database = require('./database')

app.use(cors())
app.use(express.json())

app.get("/users", (_, response) => {
  database('users')
    .then(users => response.json({ users: users }))
})

app.post("/users", (request, response) => {
  console.log(request.body)
  bcrypt.hash(request.body.password, 12, (error, hashed_pw) => {
    console.log(error)
    database('users')
      .insert({
        username: request.body.username,
        password_digest: hashed_pw
      })
      .returning(['id', 'username', 'password_digest'])
      .then(newUser => response.json({ user: newUser[0] }))
  })
})

app.post("/login", (request, response) => {
  database('users')
    .select()
    .where({ username: request.body.username })
    .first()
    .then(retrievedUser => {
      if (!retrievedUser) throw new Error('No valid user')
      return Promise.all([
        bcrypt.compare(request.body.password, retrievedUser.password_digest),
        Promise.resolve(retrievedUser)
      ])
    }).then(results => {
      const arePasswordsMatched = results[0]
      const user = results[1]

      if (!arePasswordsMatched) throw new Error("Incorrect Password. Try again")

      const payload = { username: user.username }
      const secret = "OMERTA4L"

      jwt.sign(payload, secret, (error, token) => {
        if (error) throw new Error('Sign-in Unsucessful')
        response.json({ token })
      })
    }).catch(error => {
      response.json(error.message)
    })
})

app.get('/secret-route', authenticate, (request, response) => {
  response.json({ message: `${request.user.username} logged in. GFJ!` })
  })

function authenticate (request, response, next){

  const authHeader = request.get("Authorization")
  const token = authHeader.split(" ")[1]

  const secret = "OMERTA4L"

  jwt.verify(token, secret, (error, payload) => {
    if (error) response.json()
    database('users')
      .select()
      .where({ username: payload.username })
      .first()
      .then(user => {
        request.user = user
        next()
      }).catch(error => {
        response.json({ error: error.message })
      })
})
}

app.listen(port, console.log(`Listening on Port ${port}`))