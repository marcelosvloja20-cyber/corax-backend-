/* ===================================
   CORΛX BACKEND API
=================================== */

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

app.use(express.json());
app.use(cors());

const SECRET = "corax-secret-key";

/* ===================================
   DATABASE
=================================== */

const db = new sqlite3.Database("./corax.db");

db.serialize(() => {

db.run(`
CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
email TEXT UNIQUE,
password TEXT,
balance REAL DEFAULT 100
)
`);

db.run(`
CREATE TABLE IF NOT EXISTS transactions (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER,
type TEXT,
amount REAL,
to_user TEXT,
date TEXT
)
`);

});

/* ===================================
   ROOT
=================================== */

app.get("/", (req,res)=>{
res.send("CORΛX Backend Online 🚀");
});

/* ===================================
   REGISTER
=================================== */

app.post("/register", async (req,res)=>{

const { email, password } = req.body;

if(!email || !password){
return res.status(400).json({
error:"Missing fields"
});
}

try{

const hash = await bcrypt.hash(password, 10);

db.run(
"INSERT INTO users (email,password) VALUES (?,?)",
[email, hash],
function(err){

if(err){
return res.status(400).json({
error:"User already exists"
});
}

res.json({
message:"User created successfully"
});

}
);

}catch(err){

res.status(500).json({
error:"Server error"
});

}

});

/* ===================================
   LOGIN
=================================== */

app.post("/login", (req,res)=>{

const { email, password } = req.body;

db.get(
"SELECT * FROM users WHERE email=?",
[email],
async (err,user)=>{

if(err || !user){
return res.status(401).json({
error:"Invalid credentials"
});
}

const valid = await bcrypt.compare(
password,
user.password
);

if(!valid){
return res.status(401).json({
error:"Invalid credentials"
});
}

const token = jwt.sign(
{
id:user.id,
email:user.email
},
SECRET,
{
expiresIn:"7d"
}
);

res.json({
token,
email:user.email,
balance:user.balance
});

}
);

});

/* ===================================
   AUTH MIDDLEWARE
=================================== */

function auth(req,res,next){

const token = req.headers.authorization;

if(!token){
return res.status(403).json({
error:"Access denied"
});
}

try{

const verified = jwt.verify(token, SECRET);

req.user = verified;

next();

}catch(err){

return res.status(403).json({
error:"Invalid token"
});

}

}

/* ===================================
   BALANCE
=================================== */

app.get("/balance", auth, (req,res)=>{

db.get(
"SELECT balance FROM users WHERE id=?",
[req.user.id],
(err,row)=>{

if(err || !row){
return res.status(404).json({
error:"User not found"
});
}

res.json({
balance: row.balance
});

}
);

});

/* ===================================
   SEND PAYMENT
=================================== */

app.post("/send", auth, (req,res)=>{

const { to, amount } = req.body;

if(!to || !amount){
return res.status(400).json({
error:"Missing fields"
});
}

db.get(
"SELECT * FROM users WHERE id=?",
[req.user.id],
(err,user)=>{

if(err || !user){
return res.status(404).json({
error:"User not found"
});
}

if(user.balance < amount){

return res.status(400).json({
error:"Insufficient balance"
});

}

const newBalance = user.balance - amount;

/* UPDATE BALANCE */

db.run(
"UPDATE users SET balance=? WHERE id=?",
[newBalance, req.user.id]
);

/* SAVE TRANSACTION */

db.run(
`
INSERT INTO transactions
(user_id,type,amount,to_user,date)
VALUES (?,?,?,?,?)
`,
[
req.user.id,
"Sent",
amount,
to,
new Date().toLocaleString()
]
);

res.json({
message:"Payment sent",
balance:newBalance
});

}
);

});

/* ===================================
   HISTORY
=================================== */

app.get("/history", auth, (req,res)=>{

db.all(
`
SELECT *
FROM transactions
WHERE user_id=?
ORDER BY id DESC
`,
[req.user.id],
(err,rows)=>{

if(err){
return res.status(500).json({
error:"Server error"
});
}

res.json(rows);

}
);

});

/* ===================================
   SERVER
=================================== */

const PORT = process.env.PORT || 3000;

app.listen(PORT, ()=>{

console.log(
"CORΛX backend running on port " + PORT
);

});
