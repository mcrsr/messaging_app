const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors')

const app = express();

app.use(cors())
app.use(bodyParser.json());

const SECRET_KEY = 'your_secret_key';

// Create MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'ranga',
    password: 'ranga123',
    database: 'messaging_app'
});

// Connect to the database
db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL');
});

// Middleware to authenticate JWT tokens
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// User registration
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ "error": "userame and password are required." });
    }
    // Hash the password
    const hashedPassword = bcrypt.hashSync(password, 10);

    const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.query(query, [username, hashedPassword], (err, result) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(409).send('Username already exists');
            }
            throw err;
        }
        return res.status(200).json({ "message": "User registered successfully" });
    });
});

// User login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ "error": "userame and password are required." });
    }
    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) throw err;
        if (results.length === 0) return res.status(401).send('User not found');

        const user = results[0];
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(403).send('Incorrect password');
        }

        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Send a message
app.post('/sendMessage', authenticateToken, (req, res) => {
    const { receiverId, message } = req.body;
    const senderId = req.user.id;
    
    const query = 'INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)';

    db.query(query, [senderId, receiverId, message], (err, result) => {
        if (err) throw err;
        const notificationQuery = 'INSERT INTO notifications (user_id, message_id) VALUES (?, ?)';
        db.query(notificationQuery, [receiverId, result.insertId], (err, result) => {
            if (err) throw err;
            res.status(201).json({ "message": 'Message sent and notification created' });
        });
    });
});

// Get messages for a user
app.get('/messages', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const query = `
        select 
            m.message,u.username,m.timestamp from messages m inner join users u 
        where m.sender_id=u.id and m.receiver_id=? order by timestamp desc;
    `;

    db.query(query, [userId], (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

// SSE endpoint for notifications
app.get('/notifications', (req, res) => {
    const token = req.query.token;
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;

        const userId = req.user.id;

        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');

        const query = 'SELECT * FROM notifications WHERE user_id = ? AND is_read = FALSE';

        db.query(query, [userId], (err, results) => {
            if (err) throw err;

            if (results.length > 0) {
                results.forEach((notification) => {
                    res.write(`data: New message received!\n\n`);
                });

                const markAsReadQuery = 'UPDATE notifications SET is_read = TRUE WHERE user_id = ?';
                db.query(markAsReadQuery, [userId], (err) => {
                    if (err) throw err;
                });
            }
        });

        const intervalId = setInterval(() => {
            db.query(query, [userId], (err, results) => {
                if (err) throw err;

                if (results.length > 0) {
                    results.forEach((notification) => {
                        res.write(`data: New message received!\n\n`);
                    });

                    const markAsReadQuery = 'UPDATE notifications SET is_read = TRUE WHERE user_id = ?';
                    db.query(markAsReadQuery, [userId], (err) => {
                        if (err) throw err;
                    });
                }
            });
        }, 5000);

        req.on('close', () => {
            clearInterval(intervalId);
        });
    });
});


// Start the server
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
