import express from "express";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

const db = new pg.Client({
    user: process.env.USER,
    host: process.env.HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT
})

db.connect();

app.use(bodyParser.json());

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await db.query("SELECT email, password FROM userdata WHERE email = $1", [email]);
        if (result.rows.length > 0) {
            const databasePassword = result.rows[0].password;
            const checkPassword = await bcrypt.compare(password, databasePassword);
            if (checkPassword) {
                res.send('Welcome to Ingredient Insight.');
            }
            else {
                res.status(401).send("Sorry password didn't match.");
            }
        }
        else {
            res.send("Invalid email or password.");
        }
    } catch (error) {
        console.log("Error : ", error);
        res.status(500).send("Error finding user data.");
    }
})

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const hashPassword = await bcrypt.hash(password, 10);
        await db.query("INSERT INTO userdata(name, email, password) VALUES ($1, $2, $3)",
            [name, email, hashPassword]);
        res.status(201).send("User login success.");
        console.log("Data inserted into PostgreSql.");
    } catch (error) {
        res.status(500).send("Error while login.");
        console.log("Error : ", error);
    }
})

app.listen(PORT, (req, res) => {
    console.log(`Port is running at ${PORT}`);
})