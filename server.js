require('dotenv').config()

const sqlite3 = require("sqlite3")
const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

app.use(express.json())

const db = new sqlite3.Database("./database.db")

app.get('/search', authenticateToken, (req, res) => {
    const query = "SELECT name, email FROM users WHERE email = ?"
    const values = req.token.user.email
    db.all(query, values, (error, rows) => {
        res.status(200).send(rows)
    })
})

app.post('/register', async (req, res) => {
    await createUsers()
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        const user = { name: req.body.name, password: hashedPassword, email: req.body.email }
        query = "INSERT INTO users(name, password, email) VALUES (?, ?, ?) ON CONFLICT(email) DO NOTHING"
        values = [req.body.name, hashedPassword, req.body.email]
        db.run(query, values)
        res.json(user)
        res.status(201).send()

    }catch{
        res.status(500).send()
    }
})

async function createUsers(){
    db.run(`CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE)`)
}


app.post('/login', async (req, res) => {
    await createToken()
    const query = 'SELECT * FROM users WHERE email = ?'
    const values = [req.body.email]
    db.get(query, values, (error, rows) => {
        try{
            name = rows.name
            password = rows.password
            email = rows.email
            if(name == null) {
                return res.status(400).send("Erro na autenticação")
            }
            if(bcrypt.compare(req.body.password, password)) {
                const accessToken = generateAccessToken({email})
                const queryInsert = "INSERT INTO tokens(token) VALUES (?) ON CONFLICT(token) DO NOTHING"
                db.run(queryInsert, accessToken)
                res.json({ Nome: name, Email: email , Token: accessToken})
            }   else {
                res.send('Inválido')
            }
        }catch{
            res.status(500).send
        }
    })
})

async function createToken(){
    db.run(`CREATE TABLE IF NOT EXISTS tokens(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL UNIQUE)`)
}

app.post('/logout', (req, res) => {
    const query = 'SELECT * FROM tokens WHERE token = ?'
    const values = req.body.token
    createBlacklist()

    db.get(query, [values], (err, row) => {
        if(err) console.error("Erro ao sair")
        else {
            try {
                const currentToken = row.token
                queryBlacklist = "INSERT INTO blacklist(token) VALUES (?) ON CONFLICT(token) DO NOTHING"
                valuesBlacklist = [currentToken]
                db.run(queryBlacklist, valuesBlacklist)

                jwt.verify(currentToken, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
                    if(err) return res.sendStatus(403)
                    queryDelete = "DELETE FROM tokens WHERE token = ?"
                    valuesDelete = currentToken
                    db.run(queryDelete, [valuesDelete])
            })
            } catch {
                res.status(500).send
            }

            
        }
    })
    res.sendStatus(204)
})

function createBlacklist(){
    db.run(`CREATE TABLE IF NOT EXISTS blacklist(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE
            )`)
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    const query = "SELECT * FROM blacklist WHERE token = ?"
    const values = token
    db.get(query, [values], (err, row) => {
        if(row == null){
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
                if(err) return res.sendStatus(403)
                req.token = user
                next()
            })
        }
        else{
            return res.sendStatus(403)
        }
    })
    if(token == null) return res.sendStatus(401)
}


function generateAccessToken(user) {
    return jwt.sign({user}, process.env.ACCESS_TOKEN_SECRET)
}


app.listen(3000)