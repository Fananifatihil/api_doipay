const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { db } = require('../config/db');
const { isGuest, isAuthenticated } = require('../middleware/auth');

// GET /login
router.get('/login', isGuest, (req, res) => {
  res.render('login', {
    title: 'Login - DogiPay',
    error: req.flash('error'),
    success: req.flash('success')
  });
});

// POST /login
router.post('/login', isGuest, async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await db.query('SELECT * FROM merchants WHERE email = ? AND is_active = 1', [email]);
    if (rows.length === 0) {
      req.flash('error', 'Email atau password salah');
      return res.redirect('/login');
    }

    const merchant = rows[0];
    const isMatch = await bcrypt.compare(password, merchant.password);
    if (!isMatch) {
      req.flash('error', 'Email atau password salah');
      return res.redirect('/login');
    }

    // Simpan session
    req.session.merchant = {
      id: merchant.id,
      name: merchant.name,
      email: merchant.email
    };

    req.flash('success', `Selamat datang, ${merchant.name}!`);
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    req.flash('error', 'Terjadi kesalahan server');
    res.redirect('/login');
  }
});

// GET /logout
router.get('/logout', isAuthenticated, (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// GET /register
router.get('/register', isGuest, (req, res) => {
  res.render('register', {
    title: 'Register - DogiPay',
    error: req.flash('error'),
    success: req.flash('success')
  });
});

// POST /register
router.post('/register', isGuest, async (req, res) => {
  const { name, email, password, confirm_password, phone } = req.body;

  if (password !== confirm_password) {
    req.flash('error', 'Password dan konfirmasi password tidak cocok');
    return res.redirect('/register');
  }

  try {
    // Cek email sudah ada
    const [existing] = await db.query('SELECT id FROM merchants WHERE email = ?', [email]);
    if (existing.length > 0) {
      req.flash('error', 'Email sudah terdaftar');
      return res.redirect('/register');
    }

    // Hash password
    const hashed = await bcrypt.hash(password, 10);

    // Simpan ke DB
    await db.query(
      'INSERT INTO merchants (name, email, password, phone) VALUES (?, ?, ?, ?)',
      [name, email, hashed, phone || null]
    );

    req.flash('success', 'Akun berhasil dibuat! Silakan login.');
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    req.flash('error', 'Terjadi kesalahan server');
    res.redirect('/register');
  }
});

module.exports = router;
