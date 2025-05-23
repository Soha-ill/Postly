const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const User = require('./models/User');
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const app = express();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const salt = bcrypt.genSaltSync(10);
const secret = 'asdfe45we45w345wegw345werjktjwertkj';

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    // Keep the original filename to avoid issues
    // Generate a unique filename using timestamp and random number
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, uniqueSuffix + ext);
  }
});

const uploadMiddleware = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    // Accept images only
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
      return cb(new Error('Only image files are allowed!'), false);
    }
    cb(null, true);
  }
});

app.use(cors({
  credentials: true,
  origin: 'https://postly-kappa.vercel.app',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(cookieParser());

// Debug endpoint for uploads
app.get('/uploads-test', (req, res) => {
  const files = fs.readdirSync(uploadsDir);
  res.json({ 
    message: 'Uploads directory content', 
    files,
    uploadsDir
  });
});

// Serve static files from the uploads directory
app.use('/uploads', express.static(__dirname + '/uploads'));

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/blog-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB successfully');
}).catch((err) => {
  console.error('Error connecting to MongoDB:', err);
});

// Register endpoint
app.post('/register', async (req, res) => {
  console.log("Register request body:", req.body); // ✅ NOW inside the handler

  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    const existingUser = await User.findOne({
      $or: [{ username }, { email }]
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const userDoc = await User.create({
      username,
      email,
      password: bcrypt.hashSync(password, salt),
    });

    res.json({
      id: userDoc._id,
      username: userDoc.username
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({ error: 'Username or Email and password are required' });
    }

    // Find by username or email
    const userDoc = await User.findOne({
      $or: [
        { username: identifier },
        { email: identifier }
      ]
    });

    if (!userDoc) {
      return res.status(400).json({ error: 'Invalid username/email or password' });
    }

    const passOk = bcrypt.compareSync(password, userDoc.password);
    if (passOk) {
      jwt.sign({
        username: userDoc.username,
        id: userDoc._id
      }, secret, {}, (err, token) => {
        if (err) {
          console.error('JWT signing error:', err);
          return res.status(500).json({ error: 'Error creating session' });
        }

        res.cookie('token', token, {
          httpOnly: true,
          sameSite: 'lax'
        }).json({
          id: userDoc._id,
          username: userDoc.username
        });
      });
    } else {
      res.status(400).json({ error: 'Invalid username/email or password' });
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Profile endpoint
app.get('/profile', (req,res) => {
  try {
    const {token} = req.cookies;
    if (!token) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    jwt.verify(token, secret, {}, (err, info) => {
      if (err) {
        return res.status(401).json({ error: 'Invalid token' });
      }
      res.json(info);
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout endpoint
app.post('/logout', (req,res) => {
  res.cookie('token', '').json({ message: 'Logged out successfully' });
});

// Create post endpoint
app.post('/post', uploadMiddleware.single('file'), async (req,res) => {
  try {
    const {token} = req.cookies;
    if (!token) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const {title, summary, content} = req.body;
    if (!title || !summary || !content) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'Image is required' });
    }

    jwt.verify(token, secret, {}, async (err, info) => {
      if (err) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      const postDoc = await Post.create({
        title,
        summary,
        content,
        cover: req.file.filename,
        author: info.id,
      });

      res.json(postDoc);
    });
  } catch (error) {
    console.error('Error creating post:', error);
    res.status(500).json({ error: 'Error creating post' });
  }
});

// Edit post endpoint
app.put('/post', uploadMiddleware.single('file'), async (req,res) => {
  try {
    const {token} = req.cookies;
    if (!token) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    jwt.verify(token, secret, {}, async (err, info) => {
      if (err) {
        return res.status(401).json({ error: 'Invalid token' });
      }
      
      const {id, title, summary, content} = req.body;
      const postDoc = await Post.findById(id);
      if (!postDoc) {
        return res.status(404).json({ error: 'Post not found' });
      }
      
      const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
      if (!isAuthor) {
        return res.status(403).json({ error: 'You are not the author' });
      }
      
      let newFilename = postDoc.cover;
      if (req.file) {
        newFilename = req.file.filename;
      }
      
      await Post.findByIdAndUpdate(id, {
        title,
        summary,
        content,
        cover: newFilename
      });
      
      res.json({ message: 'Post updated successfully' });
    });
  } catch (error) {
    console.error('Error updating post:', error);
    res.status(500).json({ error: 'Error updating post' });
  }
});

// Get all posts endpoint
app.get('/post', async (req,res) => {
  try {
    const posts = await Post.find()
      .populate('author', ['username'])
      .sort({createdAt: -1})
      .limit(20);
    
    // Add full image URL to each post
    const postsWithImageUrls = posts.map(post => {
      const postObject = post.toObject();
      if (postObject.cover) {
        postObject.coverUrl = `${process.env.REACT_APP_API_URL}/uploads/${postObject.cover}`;
      }
      return postObject;
    });

    res.json(postsWithImageUrls);
  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).json({ error: 'Error fetching posts' });
  }
});

// Get single post endpoint
app.get('/post/:id', async (req, res) => {
  try {
    const {id} = req.params;
    const post = await Post.findById(id).populate('author', ['username']);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    const postObject = post.toObject();
    if (postObject.cover) {
      postObject.coverUrl = `${process.env.REACT_APP_API_URL}/uploads/${postObject.cover}`;
    }
    res.json(postObject);
  } catch (error) {
    console.error('Error fetching post:', error);
    res.status(500).json({ error: 'Error fetching post' });
  }
});

// Add a simple test endpoint
app.get('/', (req, res) => {
  res.json({ message: 'API is working' });
});

// Start the server
app.listen(4000, () => {
  console.log('Server started on ${process.env.REACT_APP_API_URL}');
});
//