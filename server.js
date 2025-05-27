// server.js
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ['GET', 'POST', 'PUT', 'DELETE'], 
    credentials: true,
   }
});


// Public Folder
app.use(express.static('public'));


// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/chatapp', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB connection error:', err));
// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  room: { type: String, default: 'general' }
});

const Message = mongoose.model('Message', messageSchema);

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes
// Public Routes
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();
    
    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key'
    );

    res.status(201).json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Update user status
    await User.findByIdAndUpdate(user._id, { 
      isOnline: true,
      lastSeen: new Date()
    });

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key'
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get messages
app.get('/api/messages', authenticateToken, async (req, res) => {
  try {
    const messages = await Message.find()
      .populate('sender', 'username')
      .sort({ timestamp: -1 })
      .limit(50);
    
    res.json(messages.reverse());
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get online users
app.get('/api/users/online', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ isOnline: true })
      .select('username _id')
      .sort({ username: 1 });
    
    res.json(users);
  } catch (error) {
    console.error('Error fetching online users:', error);
        res.status(500).json({ message: 'Server error' });
  }
});

// Socket.io connection handling
const connectedUsers = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, decoded) => {
    if (err) return next(new Error('Authentication error'));
    socket.userId = decoded.userId;
    socket.username = decoded.username;
    next();
  });
});

io.on('connection', async (socket) => {
  console.log(`User ${socket.username} connected`);
  
  // Store connected user
  connectedUsers.set(socket.userId, {
    socketId: socket.id,
    username: socket.username,
    userId: socket.userId
  });

  // Update user online status
  await User.findByIdAndUpdate(socket.userId, { 
    isOnline: true,
    lastSeen: new Date()
  });

  // Broadcast updated online users list
  const onlineUsers = Array.from(connectedUsers.values()).map(user => ({
    id: user.userId,
    username: user.username
  }));
  io.emit('users_update', onlineUsers);

  // Join general room
  socket.join('general');

  // Handle new message
  socket.on('send_message', async (data) => {
    try {
      const { content, room = 'general' } = data;
      
      // Save message to database
      const message = new Message({
        sender: socket.userId,
        content,
        room
      });
      
      await message.save();
      await message.populate('sender', 'username');

      // Broadcast message to room
      io.to(room).emit('receive_message', {
        id: message._id,
        content: message.content,
        sender: {
          _id: message.sender._id,
          username: message.sender.username
        },
        timestamp: message.timestamp,
        room: message.room
      });
    } catch (error) {
      console.error('Error saving message:', error);
    }
  });

  // Handle typing indicators
  socket.on('typing', (data) => {
    socket.to(data.room || 'general').emit('user_typing', {
      username: socket.username,
      isTyping: data.isTyping
    });
  });

  // Handle disconnect
  socket.on('disconnect', async () => {
    console.log(`User ${socket.username} disconnected`);
    
    // Remove from connected users
    connectedUsers.delete(socket.userId);
    
    // Update user offline status
    await User.findByIdAndUpdate(socket.userId, { 
      isOnline: false,
      lastSeen: new Date()
    });

    // Broadcast updated online users list
    const onlineUsers = Array.from(connectedUsers.values()).map(user => ({
      id: user.userId,
      username: user.username
    }));
    io.emit('users_update', onlineUsers);
  });
});

const PORT = process.env.PORT || 3001;
// server.listen(PORT, () => {
//   console.log(`Server running on port ${PORT}`);
// });
module.exports = app;