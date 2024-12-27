import express from "express";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
let otps = {};

const db = new pg.Client({
    user: process.env.USER,
    host: process.env.HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT
});

db.connect();

app.use(bodyParser.json());

function randomOTP() {
    const accessCode = [];
    for (let i = 0; i < 4; i++) {
        accessCode.push(Math.floor(Math.random() * 10));
    }
    return accessCode.join('');
}

function generateToken(user) {
    const playload = { "id": user.id, "email": user.email };
    const SECRET_KEY = process.env.SECRET_KEY;
    const token = jwt.sign(playload, SECRET_KEY, { expiresIn: '1h' });
    return token;
}

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await db.query("SELECT email, password FROM userdata WHERE email = $1", [email]);
        if (result.rows.length > 0) {
            const userData = result.rows[0].password;
            const checkPassword = await bcrypt.compare(password, userData);
            if (checkPassword) {
                const token = generateToken(userData);
                res.send(token);
                res.status(200).json({message: 'Welcome to Ingredient Insight.', token});
            } else {
                res.status(401).send("Sorry, password didn't match.");
            }
        } else {
            res.send("Invalid email or password.");
        }
    } catch (error) {
        console.log("Error: ", error);
        res.status(500).send("Error finding user data.");
    }
});

app.post('/register', async (req, res) => {
    const { user, email, password } = req.body;
    try {
        const hashPassword = await bcrypt.hash(password, 10);
        await db.query("INSERT INTO userdata(name, email, password) VALUES ($1, $2, $3)",
            [user, email, hashPassword]);
        console.log("Data inserted into PostgreSql.");
    } catch (error) {
        res.status(500).send("Error while login.");
        console.log("Error: ", error);
    }
});

var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD,
    }
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const verify = await db.query("SELECT email FROM userdata WHERE email = $1", [email]);
        if (verify.rows.length > 0) {
            console.log("Email is present in the database.");
            const otp = randomOTP();
            otps[email] = otp; // Store OTP with email as key
            var mailOptions = {
                from: process.env.EMAIL,
                to: email,
                subject: 'Verification Mail from Ingredient Insight.',
                text: `We got a request for verification for your account. If it's not you, feel free to ignore. OTP: ${otp}`
            };
            transporter.sendMail(mailOptions, function (error, info) {
                if (error) {
                    console.log(error);
                    res.status(500).send("Error sending email.");
                } else {
                    console.log('Email sent: ' + info.response);
                    res.status(200).send("Verification email sent.");
                }
            });
        } else {
            res.status(404).send("Email not found.");
        }
    } catch (error) {
        console.log("Error: ", error);
        res.status(500).send("Error finding user data.");
    }
});

app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;

    // Debugging Step
    // console.log(`Verifying OTP for email: ${email} with provided OTP: ${otp}`);
    // console.log(`Stored OTP for email ${email}: ${otps[email]}`);

    try {
        if (otps[email] === String(otp)) {
            res.status(200).send("Verification Done. (OTP Matched)");
        } else {
            res.status(400).send("Invalid OTP.");
        }
    } catch (error) {
        console.log("Error: ", error);
        res.status(500).send("Error verifying OTP.");
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
