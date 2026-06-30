const express = require('express');
const router = express.Router();
const { db } = require('../config/db');
const { isAuthenticated } = require('../middleware/auth');

// GET /customers
router.get('/customers', isAuthenticated, async (req, res) => {
  try {
    const search = req.query.search || '';
    let query = 'SELECT id, name, email, phone, saldo, is_active, created_at FROM users';
    let params = [];

    if (search) {
      query += ' WHERE name LIKE ? OR phone LIKE ? OR email LIKE ?';
      params = [`%${search}%`, `%${search}%`, `%${search}%`];
    }

    query += ' ORDER BY created_at DESC';

    const [customers] = await db.query(query, params);

    res.render('customers', {
      title: 'Customer - DogiPay',
      merchant: req.session.merchant,
      success: req.flash('success'),
      error: req.flash('error'),
      customers,
      search
    });
  } catch (err) {
    console.error(err);
    res.render('customers', {
      title: 'Customer - DogiPay',
      merchant: req.session.merchant,
      success: [],
      error: ['Gagal memuat data'],
      customers: [],
      search: ''
    });
  }
});

module.exports = router;