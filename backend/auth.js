const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const prisma = require('../prisma/client');

const router = express.Router();

// REGISTER
// POST /api/auth/register
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Validate input exists
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // 2. Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    // 3. Hash the password
    // The '10' is the salt rounds
    const hashedPassword = await bcrypt.hash(password, 10);

    // 4. Create the user in the database
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword
      }
    });

    // 5. Return success (never return the password)
    res.status(201).json({
      message: 'User created successfully',
      userId: user.id
    });

  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// LOGIN
// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // 2. Find user by email
    const user = await prisma.user.findUnique({
      where: { email }
    });

    // 3. If no user found, return vague error
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // 4. Compare submitted password with stored hash
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // 5. Create JWT token
    const token = jwt.sign(
      { userId: user.id },           // payload
      process.env.JWT_SECRET,         // secret
      { expiresIn: '7d' }            // token expires in 7 days
    );

    // 6. Send token back to client
    res.json({
      message: 'Login successful',
      token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;