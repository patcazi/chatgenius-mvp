/****************************************************
 * A Single-File Node/Express/Socket.IO "Slack Clone"
 * w/ SQLite persistence, JWT auth, file upload,
 * real-time channels & private messaging
 * 
 * Includes a root route serving "index.html"
 * in the same folder.
 ****************************************************/

const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// -------------------
//  Sequelize Setup
// -------------------
const { Sequelize, DataTypes } = require('sequelize');

// Create or open local SQLite file "mydb.sqlite"
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: 'mydb.sqlite',
  logging: false, // Set to true to see SQL statements
});

// -----------------------
//  Define Data Models
// -----------------------
const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false,
  },
  passwordHash: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

const Channel = sequelize.define('Channel', {
  name: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false,
  },
  description: {
    type: DataTypes.STRING,
    allowNull: true,
  },
});

const Message = sequelize.define('Message', {
  text: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  threadId: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  fileData: {
    type: DataTypes.TEXT,
    allowNull: true
  }
});

const Reaction = sequelize.define('Reaction', {
  emoji: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

// Additional relationships
User.belongsToMany(Message, { through: 'Reactions' });
Message.belongsToMany(User, { through: 'Reactions' });

// Relationships
User.hasMany(Message);
Message.belongsTo(User);

Channel.hasMany(Message);
Message.belongsTo(Channel);

// Create join table for reactions
const UserReaction = sequelize.define('UserReaction', {
  emoji: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

User.belongsToMany(Message, { through: UserReaction, as: 'Reactions' });
Message.belongsToMany(User, { through: UserReaction, as: 'ReactingUsers' });

async function initDB() {
  try {
    // Drop all tables and recreate them
    await sequelize.sync({ force: true });
    
    // Create default general channel
    await Channel.create({
      name: 'general',
      description: 'General discussion'
    });
    
    console.log('SQLite database synced (mydb.sqlite).');
  } catch (err) {
    console.error('Database sync error:', err);
    process.exit(1);
  }
}

// -------------------
//  Express + Socket
// -------------------
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// -------------------
//  Config & Middleware
// -------------------
app.use(cors());
app.use(express.json());

// Use a stable JWT secret key
const JWT_SECRET = 'my_super_secret_key'; 
// For production, store in an environment variable or .env

// Ensure "uploads" folder exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads', { mode: 0o755 });
}

// Map file extensions to MIME types
const MIME_TYPES = {
  '.pdf': 'application/pdf',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.txt': 'text/plain',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.gif': 'image/gif',
  '.zip': 'application/zip'
};

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  setHeaders: (res, filePath) => {
    // Get file extension
    const ext = path.extname(filePath).toLowerCase();
    
    // Set content type based on file extension
    if (MIME_TYPES[ext]) {
      res.setHeader('Content-Type', MIME_TYPES[ext]);
    }
    
    // For PDFs and images, display inline
    if (ext === '.pdf' || ext === '.jpg' || ext === '.jpeg' || ext === '.png' || ext === '.gif') {
      res.setHeader('Content-Disposition', 'inline');
    } else {
      res.setHeader('Content-Disposition', `attachment; filename="${path.basename(filePath)}"`);
    }
    
    // Remove any restrictive headers
    res.removeHeader('X-Content-Type-Options');
    res.removeHeader('Content-Security-Policy');
  }
}));

// -------------------
//  Multer Setup
// -------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); 
  },
  filename: (req, file, cb) => {
    // Sanitize filename and add timestamp to prevent overwriting
    const sanitizedFilename = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '');
    cb(null, `${Date.now()}-${sanitizedFilename}`);
  },
});

// Define allowed file types
const ALLOWED_MIME_TYPES = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'application/pdf': 'pdf',
  'text/plain': 'txt',
  'application/msword': 'doc',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
  'application/vnd.ms-excel': 'xls',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
  'application/zip': 'zip',
  'application/x-zip-compressed': 'zip'
};

const upload = multer({
  storage,
  limits: { 
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 1 // Only allow one file per request
  },
  fileFilter: (req, file, cb) => {
    // Check if mime type is allowed
    const extension = ALLOWED_MIME_TYPES[file.mimetype];
    if (!extension) {
      return cb(new Error('Invalid file type. Only images, PDFs, Office documents, text files, and zip files are allowed.'), false);
    }

    // Verify file extension matches mime type
    const fileExtension = file.originalname.toLowerCase().split('.').pop();
    if (fileExtension !== extension && !(fileExtension === 'jpeg' && extension === 'jpg')) {
      return cb(new Error('File extension does not match its content.'), false);
    }

    cb(null, true);
  },
});

// -------------------
//  Auth Middleware
// -------------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded; // put JWT payload on req.user
    next();
  });
}

// -------------------
//  Auth Routes
// -------------------
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Check if username is taken
    const existingUser = await User.findOne({ where: { username } });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    await User.create({ username, passwordHash });
    res.json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    // Create JWT (expires in 1 hour)
    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// -------------------
//  Channel Routes
// -------------------
app.post('/channels', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'Channel name is required' });
    }

    const existingChannel = await Channel.findOne({ where: { name } });
    if (existingChannel) {
      return res.status(400).json({ error: 'Channel name already taken' });
    }

    const channel = await Channel.create({ name });
    res.status(201).json({ message: 'Channel created', channel });
  } catch (err) {
    console.error('Channel creation error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/channels', authenticateToken, async (req, res) => {
  try {
    const channels = await Channel.findAll();
    res.json(channels);
  } catch (err) {
    console.error('Channel list error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Channel membership middleware
async function verifyChannelMembership(req, res, next) {
  try {
    const channelName = req.body.channel;
    if (!channelName) {
      return res.status(400).json({ error: 'No channel specified' });
    }

    // Find the channel
    const channel = await Channel.findOne({ where: { name: channelName } });
    if (!channel) {
      return res.status(404).json({ error: 'Channel not found' });
    }

    // Get socket instance for the user
    const socketId = usernameToSocketId.get(req.user.username);
    if (!socketId) {
      return res.status(403).json({ error: 'Not connected to chat' });
    }

    const socket = io.sockets.sockets.get(socketId);
    if (!socket || !socket.rooms.has(channelName)) {
      return res.status(403).json({ error: 'Not a member of this channel' });
    }

    // Add channel to request for later use
    req.channel = channel;
    next();
  } catch (err) {
    console.error('Channel membership verification error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// -------------------
//  File Upload Routes
// -------------------

// Channel file upload
app.post('/upload/channel', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { channelName } = req.body;
    if (!channelName) {
      return res.status(400).json({ error: 'Channel name is required' });
    }

    const channel = await Channel.findOne({ where: { name: channelName } });
    if (!channel) {
      return res.status(400).json({ error: 'Channel not found' });
    }

    // Store the actual filename that was saved
    const fileData = {
      filename: req.file.filename, // This is the saved filename (with timestamp)
      originalName: req.file.originalname,
      filePath: `/uploads/${req.file.filename}`, // Use the saved filename in the path
      uploader: req.user.username,
      size: req.file.size,
      mimetype: req.file.mimetype,
      timestamp: new Date()
    };

    // Create message for the file
    const user = await User.findOne({ where: { username: req.user.username } });
    const message = await Message.create({
      text: `Shared a file: ${req.file.originalname}`,
      UserId: user.id,
      ChannelId: channel.id,
      fileData: JSON.stringify(fileData)
    });

    // Log the file data being sent
    console.log('File upload successful:', {
      savedPath: req.file.path,
      fileData: fileData,
      url: `${req.protocol}://${req.get('host')}${fileData.filePath}`
    });

    // Broadcast to channel
    io.to(channelName).emit('message', {
      id: message.id,
      text: message.text,
      username: req.user.username,
      timestamp: message.createdAt,
      fileData: fileData,
      reactions: {}
    });

    res.status(200).json({
      message: 'File uploaded successfully',
      fileData
    });
  } catch (err) {
    console.error('File upload error:', err);
    if (req.file) {
      fs.unlink(req.file.path, (unlinkErr) => {
        if (unlinkErr) console.error('Error deleting file:', unlinkErr);
      });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Private message file upload
app.post('/upload/private', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { targetUser, room } = req.body;
    if (!targetUser || !room || !room.startsWith('private:')) {
      return res.status(400).json({ error: 'Invalid private message details' });
    }

    const fileData = {
      filename: req.file.filename,
      originalName: req.file.originalname,
      filePath: `/uploads/${req.file.filename}`,
      uploader: req.user.username,
      size: req.file.size,
      mimetype: req.file.mimetype,
      timestamp: new Date()
    };

    // Send file data to private room
    io.to(room).emit('privateMessage', {
      id: Date.now().toString(),
      text: `Shared a file: ${req.file.originalname}`,
      username: req.user.username,
      timestamp: new Date(),
      isPrivate: true,
      targetUser,
      fileData
    });

    res.status(200).json({
      message: 'File shared successfully',
      fileData
    });
  } catch (err) {
    console.error('Private file share error:', err);
    if (req.file) {
      fs.unlink(req.file.path, (unlinkErr) => {
        if (unlinkErr) console.error('Error deleting file:', unlinkErr);
      });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// -------------------
//  Socket.IO
// -------------------
let socketIdToUsername = new Map();
let usernameToSocketId = new Map();

function sanitizeMessage(text) {
  return text.trim().slice(0, 1000); // limit to 1000 chars
}

io.on('connection', (socket) => {
  let currentChannel = null;
  console.log(`New connection: ${socket.id}`);

  // When user logs in
  socket.on('login', async (username) => {
    socketIdToUsername.set(socket.id, username);
    usernameToSocketId.set(username, socket.id);
    
    try {
      // Create general channel if it doesn't exist
      const [generalChannel] = await Channel.findOrCreate({
        where: { name: 'general' },
        defaults: { description: 'General discussion' }
      });

      // Send current channels list
      const channels = await Channel.findAll();
      socket.emit('updateChannels', channels.map(c => c.name));
      
      // Auto-join general channel
      socket.join('general');
      currentChannel = 'general';
      
      // Send online users
      io.emit('updateUsers', Array.from(socketIdToUsername.values()));

      // Send channel history
      const messages = await Message.findAll({
        where: { 
          ChannelId: generalChannel.id,
          threadId: null
        },
        include: [
          { model: User, attributes: ['username'] },
          { 
            model: User, 
            as: 'ReactingUsers',
            attributes: ['username'],
            through: { attributes: ['emoji'] }
          }
        ],
        order: [['createdAt', 'DESC']],
        limit: 50
      });

      socket.emit('message', messages.map(msg => ({
        id: msg.id,
        text: msg.text,
        username: msg.User.username,
        timestamp: msg.createdAt,
        reactions: msg.ReactingUsers.reduce((acc, user) => {
          const emoji = user.UserReaction.emoji;
          if (!acc[emoji]) acc[emoji] = [];
          acc[emoji].push(user.username);
          return acc;
        }, {})
      })));
    } catch (err) {
      console.error('Login error:', err);
    }
  });

  // Join channel
  socket.on('joinChannel', async (channelName) => {
    try {
      const username = socketIdToUsername.get(socket.id);
      console.log(`[JOIN] User ${username} attempting to join channel: ${channelName}`);
      
      // Leave current channel if any
      if (socket.currentChannel) {
        console.log(`[JOIN] Leaving current channel: ${socket.currentChannel}`);
        socket.leave(socket.currentChannel);
      }
      
      const channel = await Channel.findOne({ where: { name: channelName } });
      if (!channel) {
        console.error(`[JOIN] Channel not found: ${channelName}`);
        return socket.emit('error', { message: 'Channel not found' });
      }

      socket.join(channelName);
      socket.currentChannel = channelName; // Store channel on socket instance
      currentChannel = channelName; // Update the global state
      console.log(`[JOIN] User ${username} joined channel: ${channelName}`);

      const messages = await Message.findAll({
        where: { 
          ChannelId: channel.id,
          threadId: null
        },
        include: [
          { 
            model: User,
            attributes: ['username'],
            required: true
          },
          { 
            model: User, 
            as: 'ReactingUsers',
            attributes: ['username'],
            through: { attributes: ['emoji'] }
          }
        ],
        order: [['createdAt', 'DESC']],
        limit: 50
      });

      // Safely format messages
      const formattedMessages = messages.map(msg => ({
        id: msg.id,
        text: msg.text,
        username: msg.User ? msg.User.username : 'Unknown User',
        timestamp: msg.createdAt,
        reactions: msg.ReactingUsers ? msg.ReactingUsers.reduce((acc, user) => {
          if (user.UserReaction) {
            const emoji = user.UserReaction.emoji;
            if (!acc[emoji]) acc[emoji] = [];
            acc[emoji].push(user.username);
          }
          return acc;
        }, {}) : {}
      }));

      socket.emit('message', formattedMessages);
    } catch (err) {
      console.error('[JOIN] Error joining channel:', err);
      socket.emit('error', { message: 'Failed to join channel' });
    }
  });

  // Handle new message
  socket.on('message', async (data) => {
    const username = socketIdToUsername.get(socket.id);
    if (!username) {
      console.error('[MSG] No username found for socket:', socket.id);
      return socket.emit('error', { message: 'Not authenticated' });
    }

    try {
      console.log(`[MSG] Attempting to send message from ${username} in channel ${data.channel}`);
      
      const user = await User.findOne({ where: { username } });
      if (!user) {
        console.error('[MSG] User not found:', username);
        return socket.emit('error', { message: 'User not found' });
      }

      let channel;
      if (data.threadId) {
        // For thread messages, use the provided channel name or find it from parent message
        if (data.channel) {
          channel = await Channel.findOne({ where: { name: data.channel } });
        } else {
          const parentMessage = await Message.findByPk(data.threadId);
          if (!parentMessage) {
            console.error('[MSG] Thread not found:', data.threadId);
            return socket.emit('error', { message: 'Thread not found' });
          }
          channel = await Channel.findByPk(parentMessage.ChannelId);
        }
      } else {
        // For regular messages, use the channel name from the client
        const channelName = data.channel;
        console.log('[MSG] Looking for channel:', channelName);
        
        if (!channelName) {
          console.error('[MSG] No channel specified in message data');
          return socket.emit('error', { message: 'No channel specified' });
        }
        
        channel = await Channel.findOne({ where: { name: channelName } });
        if (!channel) {
          console.error('[MSG] Channel not found:', channelName);
          return socket.emit('error', { message: 'Channel not found' });
        }
      }

      console.log(`[MSG] Creating message in channel ${channel.name} by user ${username}`);

      // Create message with proper associations
      const message = await Message.create({
        text: sanitizeMessage(data.text),
        UserId: user.id,
        ChannelId: channel.id,
        threadId: data.threadId || null
      });

      // Format the message for sending immediately
      const messageData = {
        id: message.id,
        text: message.text,
        username: username, // Use the username we already have
        timestamp: message.createdAt,
        threadId: message.threadId,
        reactions: {} // Start with empty reactions for new message
      };

      if (data.threadId) {
        console.log(`[MSG] Sending thread message to thread:${data.threadId}`);
        io.to(`thread:${data.threadId}`).emit('message', messageData);
        io.to(channel.name).emit('threadUpdate', {
          messageId: data.threadId,
          lastReply: messageData
        });
      } else {
        console.log(`[MSG] Sending message to channel: ${channel.name}`);
        io.to(channel.name).emit('message', messageData);
      }
    } catch (err) {
      console.error('[MSG] Message error:', err);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // Handle reactions
  socket.on('addReaction', async ({ messageId, emoji }) => {
    const username = socketIdToUsername.get(socket.id);
    if (!username) return;

    try {
      const user = await User.findOne({ where: { username } });
      const message = await Message.findByPk(messageId, {
        include: [{ model: Channel }]
      });
      if (!user || !message) return;

      // Add reaction
      await UserReaction.create({
        UserId: user.id,
        MessageId: messageId,
        emoji
      });

      // Get updated reactions
      const reactions = await UserReaction.findAll({
        where: { MessageId: messageId },
        include: [{ model: User, attributes: ['username'] }]
      });

      // Format reactions
      const formattedReactions = reactions.reduce((acc, reaction) => {
        if (!acc[reaction.emoji]) acc[reaction.emoji] = [];
        acc[reaction.emoji].push(reaction.User.username);
        return acc;
      }, {});

      // Broadcast updated reactions
      if (message.threadId) {
        io.to(`thread:${message.threadId}`).emit('updateReactions', {
          messageId,
          reactions: formattedReactions
        });
      } else {
        io.to(message.Channel.name).emit('updateReactions', {
          messageId,
          reactions: formattedReactions
        });
      }
    } catch (err) {
      console.error('Reaction error:', err);
    }
  });

  socket.on('toggleReaction', async ({ messageId, emoji }) => {
    const username = socketIdToUsername.get(socket.id);
    if (!username) return;

    try {
      const user = await User.findOne({ where: { username } });
      const message = await Message.findByPk(messageId, {
        include: [{ model: Channel }]
      });
      if (!user || !message) return;

      // Check if reaction exists
      const existingReaction = await UserReaction.findOne({
        where: {
          UserId: user.id,
          MessageId: messageId,
          emoji
        }
      });

      if (existingReaction) {
        await existingReaction.destroy();
      } else {
        await UserReaction.create({
          UserId: user.id,
          MessageId: messageId,
          emoji
        });
      }

      // Get updated reactions
      const reactions = await UserReaction.findAll({
        where: { MessageId: messageId },
        include: [{ model: User, attributes: ['username'] }]
      });

      const formattedReactions = reactions.reduce((acc, reaction) => {
        if (!acc[reaction.emoji]) acc[reaction.emoji] = [];
        acc[reaction.emoji].push(reaction.User.username);
        return acc;
      }, {});

      if (message.threadId) {
        io.to(`thread:${message.threadId}`).emit('updateReactions', {
          messageId,
          reactions: formattedReactions
        });
      } else {
        io.to(message.Channel.name).emit('updateReactions', {
          messageId,
          reactions: formattedReactions
        });
      }
    } catch (err) {
      console.error('Toggle reaction error:', err);
    }
  });

  // Handle private messaging
  socket.on('startPrivateMessage', async ({ targetUser }) => {
    const senderUsername = socketIdToUsername.get(socket.id);
    if (!senderUsername) {
      return socket.emit('error', { message: 'Not authenticated' });
    }

    if (senderUsername === targetUser) {
      return socket.emit('error', { message: 'Cannot start chat with yourself' });
    }

    const targetSocketId = usernameToSocketId.get(targetUser);
    if (!targetSocketId) {
      return socket.emit('error', { message: 'User is not online' });
    }

    // Create a unique room name for the private chat
    const roomName = `private:${[senderUsername, targetUser].sort().join('_')}`;

    // Join both users to the room
    socket.join(roomName);
    io.sockets.sockets.get(targetSocketId)?.join(roomName);

    console.log(`Private room: ${roomName} (between ${senderUsername} & ${targetUser})`);

    // Send room info to both users
    socket.emit('privateMessageStarted', {
      room: roomName,
      user: targetUser
    });
    
    // Also notify the target user about the private chat
    io.to(targetSocketId).emit('privateMessageStarted', {
      room: roomName,
      user: senderUsername
    });
  });

  socket.on('sendPrivateMessage', async (data) => {
    const senderUsername = socketIdToUsername.get(socket.id);
    if (!senderUsername) return;

    try {
      const { room, text, targetUser } = data;
      
      if (!room.startsWith('private:')) {
        return socket.emit('error', { message: 'Invalid private message room' });
      }

      const sanitizedText = sanitizeMessage(text);
      if (!sanitizedText) {
        return socket.emit('error', { message: 'Message cannot be empty' });
      }

      const messageData = {
        id: Date.now().toString(),
        text: sanitizedText,
        username: senderUsername,
        timestamp: new Date(),
        isPrivate: true,
        targetUser
      };

      // Send to all users in the private room
      io.to(room).emit('privateMessage', messageData);
    } catch (err) {
      console.error('Private message error:', err);
      socket.emit('error', { message: 'Failed to send private message' });
    }
  });

  // Create new channel
  socket.on('createChannel', async (data) => {
    const username = socketIdToUsername.get(socket.id);
    if (!username) {
      console.error('[CREATE] No username found for socket:', socket.id);
      return socket.emit('error', { message: 'Not authenticated' });
    }

    try {
      const { name, description } = data;
      
      // Validate channel name
      if (!name || name.length < 1) {
        return socket.emit('error', { message: 'Channel name is required' });
      }

      // Check if channel exists
      const existingChannel = await Channel.findOne({ where: { name } });
      if (existingChannel) {
        return socket.emit('error', { message: 'Channel already exists' });
      }

      // Create channel
      const channel = await Channel.create({ name, description });
      
      // Get updated channel list
      const channels = await Channel.findAll();
      io.emit('updateChannels', channels.map(c => c.name));
      
      // Auto-join the creator to the new channel
      socket.join(name);
      socket.currentChannel = name;
      
      // Send success message
      socket.emit('success', { 
        message: 'Channel created successfully',
        channel: name
      });

      // Send empty message list for the new channel
      socket.emit('message', []);
    } catch (err) {
      console.error('[CREATE] Channel creation error:', err);
      socket.emit('error', { message: 'Failed to create channel' });
    }
  });

  // On disconnect
  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
    const username = socketIdToUsername.get(socket.id);
    if (username) {
      socketIdToUsername.delete(socket.id);
      usernameToSocketId.delete(username);
      io.emit('updateUsers', Array.from(socketIdToUsername.values()));
    }
  });

  // Handle thread messages
  socket.on('getThread', async (messageId) => {
    try {
      const messages = await Message.findAll({
        where: { 
          threadId: messageId 
        },
        include: [
          { 
            model: User,
            attributes: ['username']
          },
          { 
            model: User, 
            as: 'ReactingUsers',
            attributes: ['username'],
            through: { attributes: ['emoji'] }
          }
        ],
        order: [['createdAt', 'ASC']]
      });

      // Join thread room
      socket.join(`thread:${messageId}`);

      socket.emit('message', messages.map(msg => ({
        id: msg.id,
        text: msg.text,
        username: msg.User.username,
        timestamp: msg.createdAt,
        threadId: msg.threadId,
        reactions: msg.ReactingUsers.reduce((acc, user) => {
          const emoji = user.UserReaction.emoji;
          if (!acc[emoji]) acc[emoji] = [];
          acc[emoji].push(user.username);
          return acc;
        }, {})
      })));
    } catch (err) {
      console.error('Thread fetch error:', err);
      socket.emit('error', { message: 'Failed to fetch thread messages' });
    }
  });
});

// --------------------
//  Serve index.html
// --------------------
app.get('/', (req, res) => {
  // Make sure you have an "index.html" in the same folder as server.js
  res.sendFile(path.join(__dirname, 'index.html'));
});

// --------------------
//  Global Error Handler
// --------------------
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'An error occurred', details: err.message });
});

// --------------------
//  Start the Server
// --------------------
const PORT = process.env.PORT || 3000;

initDB().then(() => {
  server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}).catch((err) => {
  console.error('Failed to sync DB:', err);
});
