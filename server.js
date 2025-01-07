// server.js

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// Create an Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// In-memory user list for credentials (resets on server restart)
let users = []; // { username, passwordHash }

// ***** NEW: onlineUsers for presence *****
let onlineUsers = {}; // { socketId: 'username' }

// Registration endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if username is taken
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash the password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Store user in memory
    users.push({ username, passwordHash });

    res.json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user by username
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    // Compare the plain-text password with the stored hash
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    // If valid, create a token
    // NOTE: In production, replace 'YOUR_SECRET_KEY' with a secure env variable.
    const token = jwt.sign({ username }, 'YOUR_SECRET_KEY', { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create an HTTP server from the Express app
const server = http.createServer(app);

// Create a Socket.IO server, attaching it to the HTTP server
const io = new Server(server);

// Socket.IO connection event
io.on('connection', (socket) => {
  console.log(`A user connected: ${socket.id}`);

  // ***** NEW: setUsername event for presence *****
  socket.on('setUsername', (username) => {
    // Link this socket.id to the given username
    onlineUsers[socket.id] = username;
    console.log(`${socket.id} is now known as ${username}`);

    // Broadcast the updated user list to all
    io.emit('onlineUsers', Object.values(onlineUsers));
  });

  // Let a user join a channel/room
  socket.on('joinRoom', (roomName) => {
    socket.join(roomName);
    console.log(`${socket.id} joined room: ${roomName}`);
  });

  // New event for room-specific messaging
  socket.on('sendRoomMessage', (data) => {
    // data looks like: { room: 'general', username: 'alice', text: 'Hello!' }
    console.log(`Room ${data.room} message from ${data.username}: ${data.text}`);
    // Emit to everyone *in that room* via "roomMessage"
    io.to(data.room).emit('roomMessage', data);
  });

  // Listen for a user disconnecting
  socket.on('disconnect', () => {
    console.log(`A user disconnected: ${socket.id}`);

    // ***** NEW: remove from onlineUsers *****
    delete onlineUsers[socket.id];
    // Broadcast updated online user list
    io.emit('onlineUsers', Object.values(onlineUsers));
  });
});

// Start the server on port 3000 (or any available port)
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server listening at http://localhost:${PORT}`);
});
