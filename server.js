const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Create an Express app
const app = express();

// Environment variables (with fallback for development)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// In-memory storage (would be replaced with a database in production)
let users = []; // { username, passwordHash }
let uploadedFiles = []; // { filename, filePath, uploader }
let onlineUsers = {}; // { socketId: 'username' }

// Set up storage for file uploads with security measures
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    // Sanitize filename and add timestamp
    const sanitizedFilename = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '');
    cb(null, `${Date.now()}-${sanitizedFilename}`);
  },
});

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    // Only allow certain file types
    if (!file.mimetype.match(/^(image\/|application\/pdf)/)) {
      return cb(new Error('Invalid file type'), false);
    }
    cb(null, true);
  }
});

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Registration endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Basic input validation
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

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

    // Basic input validation
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user by username
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    // Compare the password with the stored hash
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    // Create a token
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// File upload endpoint (protected)
app.post('/upload', authenticateToken, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Add the uploaded file to the list
    const fileData = {
      filename: req.file.filename,
      filePath: `/uploads/${req.file.filename}`,
      uploader: req.user.username,
    };
    uploadedFiles.push(fileData);

    // Broadcast the new file to all connected clients
    io.emit('newFile', fileData);

    res.status(200).json({
      message: 'File uploaded successfully',
      filename: fileData.filename,
      filePath: fileData.filePath,
    });
  } catch (err) {
    console.error('File upload error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create an HTTP server from the Express app
const server = http.createServer(app);

// Create a Socket.IO server
const io = new Server(server);

// Message sanitization helper
const sanitizeMessage = (text) => {
  return text
    .trim()
    .slice(0, 1000); // Limit message length
};

// Socket.IO connection handler
io.on('connection', (socket) => {
  console.log(`A user connected: ${socket.id}`);

  // Set username and track online users
  socket.on('setUsername', (username) => {
    onlineUsers[socket.id] = username;
    console.log(`${socket.id} is now known as ${username}`);
    io.emit('onlineUsers', Object.values(onlineUsers));
  });

  // Join room with proper room management
  socket.on('joinRoom', async (newRoom) => {
    // Leave previous rooms first
    const rooms = Array.from(socket.rooms);
    rooms.forEach(room => {
      if (room !== socket.id) socket.leave(room);
    });
    
    // Join new room
    socket.join(newRoom);
    console.log(`${socket.id} joined room: ${newRoom}`);
  });

  // Handle room messages with sanitization
  socket.on('sendRoomMessage', (msgObject) => {
    const sanitizedText = sanitizeMessage(msgObject.text);
    if (!sanitizedText) return;

    io.to(msgObject.room).emit('roomMessage', {
      ...msgObject,
      text: sanitizedText
    });
  });

  // Handle private messaging
  socket.on('startPrivateMessage', ({ targetUser }, callback) => {
    const sender = onlineUsers[socket.id];
    if (!sender) {
      return callback({ error: 'Sender not recognized' });
    }

    const targetSocketId = Object.keys(onlineUsers).find(
      (id) => onlineUsers[id] === targetUser
    );

    if (!targetSocketId) {
      return callback({ error: `User ${targetUser} is not online` });
    }

    // Create a unique private room
    const privateRoom = [socket.id, targetSocketId].sort().join('-');
    socket.join(privateRoom);
    io.sockets.sockets.get(targetSocketId)?.join(privateRoom);

    console.log(`Private room created: ${privateRoom} for ${sender} and ${targetUser}`);
    callback({ room: privateRoom });
  });

  // Handle private messages with sanitization
  socket.on('sendPrivateMessage', ({ room, text }) => {
    const sender = onlineUsers[socket.id];
    if (!sender) return;

    const sanitizedText = sanitizeMessage(text);
    if (!sanitizedText) return;

    console.log(`Private message in ${room} from ${sender}: ${sanitizedText}`);
    io.to(room).emit('privateMessage', { sender, text: sanitizedText });
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log(`A user disconnected: ${socket.id}`);
    delete onlineUsers[socket.id];
    io.emit('onlineUsers', Object.values(onlineUsers));
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'An error occurred',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined 
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server listening at http://localhost:${PORT}`);
});
