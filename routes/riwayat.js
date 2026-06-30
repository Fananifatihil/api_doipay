const express = require('express');
const router = express.Router();
const { db } = require('../config/db');
const { isAuthenticated } = require('../middleware/auth');

// GET /riwayat
router.get('/riwayat', isAuthenticated, async (req, res) => {
  try {
    const merchantId = req.session.merchant.id;
    const page = parseInt(req.query.page) || 1;
    const limit = 15;
    const offset = (page - 1) * limit;
    const search = req.query.search || '';

    let where = 'WHERE t.merchant_id = ?';
    let params = [merchantId];

    if (search) {
      where += ' AND (u.name LIKE ? OR u.phone LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }

    // Total rows untuk pagination
    const [countRows] = await db.query(`
      SELECT COUNT(*) as total
      FROM topup_transactions t
      JOIN users u ON t.user_id = u.id
      ${where}
    `, params);

    const total = countRows[0].total;
    const totalPages = Math.ceil(total / limit);

    // Data transaksi
    const [transactions] = await db.query(`
      SELECT t.*, u.name as customer_name, u.phone as customer_phone
      FROM topup_transactions t
      JOIN users u ON t.user_id = u.id
      ${where}
      ORDER BY t.created_at DESC
      LIMIT ? OFFSET ?
    `, [...params, limit, offset]);

    res.render('riwayat', {
      title: 'Riwayat - DogiPay',
      merchant: req.session.merchant,
      success: req.flash('success'),
      error: req.flash('error'),
      transactions,
      search,
      currentPage: page,
      totalPages,
      total
    });
  } catch (err) {
    console.error(err);
    res.render('riwayat', {
      title: 'Riwayat - DogiPay',
      merchant: req.session.merchant,
      success: [], error: ['Gagal memuat data'],
      transactions: [], search: '',
      currentPage: 1, totalPages: 1, total: 0
    });
  }
});

module.exports = router;