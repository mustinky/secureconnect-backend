// Dependencies
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const port = 3000;
const secretKey = 'your_super_secret_key_here';

app.use(bodyParser.json());

// Global data
let products = {};
let users = {};
let chatLog = [];
const refreshTokens = new Set();
const onlineUsers = new Map();
const ONLINE_TIMEOUT_MS = 1 * 60 * 1000; // 1 minute

// Paths
const chatLogsDir = path.join(__dirname, 'chat_logs');
const chatLogFile = path.join(chatLogsDir, 'chatlog.txt');

// Setup directories
if (!fs.existsSync(chatLogsDir)) {
  fs.mkdirSync(chatLogsDir, { recursive: true });
  console.log('Created chat_logs directory');
}

if (!fs.existsSync(chatLogFile)) {
  fs.writeFileSync(chatLogFile, '', 'utf-8');
  console.log('Created empty chatlog.txt file');
}

// Load products
try {
  products = JSON.parse(fs.readFileSync('products.json'));
} catch (err) {
  console.error('Failed to load products.json', err);
}

// Load users
if (fs.existsSync('users.json')) {
  try {
    users = JSON.parse(fs.readFileSync('users.json'));
  } catch (err) {
    users = {};
  }
}

// Load chat log
try {
  const content = fs.readFileSync(chatLogFile, 'utf-8').trim();
  if (content === '') {
    chatLog = [];
  } else {
    chatLog = content
      .split('\n')
      .map(line => {
        try {
          return JSON.parse(line);
        } catch {
          console.warn('Skipping malformed chat line:', line);
          return null;
        }
      })
      .filter(Boolean);
  }
} catch (err) {
  console.error('Failed to load chat logs', err);
  chatLog = [];
}

// Save helpers
function saveUsers() {
  try {
    fs.writeFileSync('users.json', JSON.stringify(users, null, 4));
  } catch (err) {
    console.error('Failed to save users.json', err);
  }
}
function saveChatLog() {
  try {
    const recentMessages = chatLog.slice(-100);
    const data = recentMessages.map(entry => JSON.stringify(entry)).join('\n') + '\n';
    fs.writeFileSync(chatLogFile, data, 'utf-8');
  } catch (err) {
    console.error('Failed to save chat log', err);
  }
}

const normalizeHWID = hwid => hwid.trim().toLowerCase();
function isProductExpired(product) {
  return product.expiresAt && Date.now() > product.expiresAt;
}

// New helper: get file modified time
function getFileModifiedTime(filename) {
  try {
    const filePath = path.join(__dirname, 'dll_files', filename);
    const stats = fs.statSync(filePath);
    return stats.mtime.toISOString();
  } catch (err) {
    console.warn(`Failed to get modified time for ${filename}`, err);
    return null;
  }
}

// Rate limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Too many requests' },
});

app.post('/register', authLimiter);
app.post('/auth', authLimiter);

// Registration
app.post('/register', async (req, res) => {
  const { username, password, hwid } = req.body;
  if (!username || !password || !hwid) return res.status(400).send('Missing fields');
  if (users[username]) return res.status(409).send('Username exists');

  for (const u in users) {
    if (normalizeHWID(users[u].hwid) === normalizeHWID(hwid) && Date.now() < users[u].accessExpires) {
      return res.status(403).send('HWID already registered');
    }
  }

  try {
    const hash = await bcrypt.hash(password, 10);
   const now = Date.now();
users[username] = {
  password: hash,
  hwid,
  products: [],
  accessExpires: now + 3 * 24 * 60 * 60 * 1000, // ⬅ 3 days
  suspended: false,
  suspendReason: '',
  createdAt: now,
  lastLogin: null,
  totalTimeUsed: 0,
  lastLoginStart: null
};
    saveUsers();
    res.send('Registered');
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal server error');
  }
});

// Authentication
app.post('/auth', async (req, res) => {
  const { username, password, hwid } = req.body;
  const user = users[username];
  if (!user) return res.status(401).json({ error: 'Invalid user' });
  if (normalizeHWID(user.hwid) !== normalizeHWID(hwid)) return res.status(403).json({ error: 'HWID mismatch' });
  if (user.suspended) return res.status(403).json({ error: user.suspendReason });
  if (Date.now() > user.accessExpires) return res.status(403).json({ error: 'Access expired' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(403).json({ error: 'Wrong password' });

  const now = Date.now();
  if (user.lastLoginStart) user.totalTimeUsed += now - user.lastLoginStart;
  user.lastLogin = now;
  user.lastLoginStart = now;
  onlineUsers.set(username, now);

  const accessToken = jwt.sign({ username }, secretKey, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ username }, secretKey, { expiresIn: '7d' });
  refreshTokens.add(refreshToken);

  const validProducts = user.products.filter(p => products[p.id]?.enabled && !isProductExpired(p));
  saveUsers();

  res.json({
    accessToken,
    refreshToken,
    products: validProducts.map(p => ({
      id: p.id,
      name: products[p.id].name,
      filename: products[p.id].filename,
      exe: products[p.id].exe || null,
      expiresAt: p.expiresAt ? new Date(p.expiresAt).toISOString() : null,
      lastUpdated: getFileModifiedTime(products[p.id].filename)
    })),
    expires: user.accessExpires
  });
});

// JWT middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });
  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    onlineUsers.set(user.username, Date.now());
    next();
  });
}

// online users endpoint
app.get('/online-users', (req, res) => {
  const usersOnline = Array.from(onlineUsers.keys());
  res.json({ count: usersOnline.length, users: usersOnline });
});

// download endpoint with Last-Modified
app.get('/download/:productId', (req, res) => {
  const product = products[req.params.productId];
  if (!product || !product.enabled) return res.status(404).send('Not found');
  const filePath = path.join(__dirname, 'dll_files', product.filename);
  try {
    const stats = fs.statSync(filePath);
    res.setHeader('Last-Modified', stats.mtime.toUTCString());
  } catch { /** ignore */ }
  res.download(filePath);
});

// refresh-token
app.post('/refresh-token', (req, res) => {
  const { token } = req.body;
  if (!token || !refreshTokens.has(token)) return res.status(403).json({ error: 'Invalid token' });
  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    const newToken = jwt.sign({ username: user.username }, secretKey, { expiresIn: '15m' });
    res.json({ accessToken: newToken });
  });
});

// logout
app.post('/logout', (req, res) => {
  const { token } = req.body;
  if (refreshTokens.delete(token)) return res.json({ message: 'Logged out' });
  res.status(400).json({ error: 'Invalid or expired' });
});

// user_info
app.get('/user_info', authenticateToken, (req, res) => {
  const user = users[req.user.username];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const validProducts = user.products.filter(p => products[p.id]?.enabled && !isProductExpired(p));
  res.json({
    username: req.user.username,
    hwid: user.hwid,
    accessExpires: user.accessExpires,
    totalTimeUsed: user.totalTimeUsed,
    lastLogin: user.lastLogin,
    createdAt: user.createdAt,
    products: validProducts.map(p => ({
      id: p.id,
      name: products[p.id]?.name || 'Unknown',
      filename: products[p.id]?.filename || null,
      exe: products[p.id]?.exe || null,
      expiresAt: p.expiresAt || null,
      lastUpdated: getFileModifiedTime(products[p.id]?.filename || '')
    }))
  });
});

// Cleanup online users
setInterval(() => {
  const now = Date.now();
  for (const [username, lastActive] of onlineUsers.entries()) {
    if (now - lastActive > ONLINE_TIMEOUT_MS) {
      onlineUsers.delete(username);
    }
  }
}, 60 * 1000);

// Socket.IO
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('Missing token'));
  jwt.verify(token, secretKey, (err, user) => {
    if (err) return next(new Error('Invalid token'));
    socket.user = user;
    next();
  });
});

// Basic chat rate-limit (Socket)
const chatRateLimits = new Map();

io.on('connection', (socket) => {
  const username = socket.user.username;
  socket.emit('chat:history', chatLog);
  io.emit('chat:status', `${username} joined`);
  socket.on('chat:message', (msg) => {
    const now = Date.now();
    const last = chatRateLimits.get(username) || 0;
    if (now - last < 1000) return;   // silently ignore messages sent too fast
    chatRateLimits.set(username, now);
    const entry = { username, message: msg, timestamp: now };
    chatLog.push(entry);
    io.emit('chat:message', entry);
  });
  socket.on('disconnect', () => {
    onlineUsers.delete(username);
    io.emit('chat:status', `${username} left`);
  });
});


// REST chat endpoint with protections
const chatMessageTimestamps = new Map();
const recentMessages = new Map();
const MESSAGE_INTERVAL_MS = 1000;
const MAX_MESSAGE_LENGTH = 500;

function isSpamMessage(username, message) {
  const lastMsg = recentMessages.get(username);
  recentMessages.set(username, message);
  if (lastMsg && lastMsg === message) return 'Duplicate message';
  if (message.length > 10) {
    const capRatio = message.replace(/[^A-Z]/g, '').length / message.length;
    if (capRatio > 0.8) return 'Too much capital letters';
  }
  if (message.length < 2) return 'Too short';
  return null;
}

app.post('/send-message', authenticateToken, (req, res) => {
  const username = req.user.username;
  let message = req.body.message;
  if (typeof message !== 'string' || message.trim().length === 0)
    return res.status(400).json({ error: 'Message is required' });
  message = message.trim().slice(0, MAX_MESSAGE_LENGTH);
  const now = Date.now();
  const lastTime = chatMessageTimestamps.get(username) || 0;
  if (now - lastTime < MESSAGE_INTERVAL_MS)
    return res.status(429).json({ error: 'You are sending messages too fast' });
  chatMessageTimestamps.set(username, now);
  const spamReason = isSpamMessage(username, message);
  if (spamReason)
    return res.status(429).json({ error: `Spam detected: ${spamReason}` });
  const entry = { username, message, timestamp: now };
  chatLog.push(entry);
  if (chatLog.length > 100) chatLog = chatLog.slice(-100);
  saveChatLog();
  io.emit('chat:message', entry);
  res.json({ status: 'Message sent' });
});

// Chat cleanup interval
setInterval(() => {
  const now = Date.now();
  for (const [user, ts] of chatMessageTimestamps) {
    if (now - ts > 60 * 1000) chatMessageTimestamps.delete(user);
  }
  for (const user of recentMessages.keys()) {
    if (!chatMessageTimestamps.has(user)) recentMessages.delete(user);
  }
}, 60 * 1000);

app.get('/chat-history', authenticateToken, (req, res) => {
  res.json({ messages: chatLog.slice(-100) }); // wrap in { messages: [...] }
});

// Start server
server.listen(process.env.PORT || port, () => {
  console.log(`Server running on http://${process.env.RENDER_EXTERNAL_HOSTNAME || 'localhost'}:${process.env.PORT || port}`);
});

