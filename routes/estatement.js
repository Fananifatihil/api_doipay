const express = require('express');
const router = express.Router();
const { db } = require('../config/db');
const { isAuthenticated } = require('../middleware/auth');

router.get('/estatement', isAuthenticated, async (req, res) => {
  try {
    const merchantId = req.session.merchant.id;

    // Ambil bulan & tahun dari query, default bulan ini
    const now = new Date();
    const month = parseInt(req.query.month) || (now.getMonth() + 1);
    const year = parseInt(req.query.year) || now.getFullYear();

    // Transaksi bulan yang dipilih
    const [transactions] = await db.query(`
      SELECT t.*, u.name as customer_name, u.phone as customer_phone
      FROM topup_transactions t
      JOIN users u ON t.user_id = u.id
      WHERE t.merchant_id = ?
        AND MONTH(t.created_at) = ?
        AND YEAR(t.created_at) = ?
      ORDER BY t.created_at DESC
    `, [merchantId, month, year]);

    // Summary statistik
    const [summary] = await db.query(`
      SELECT
        COUNT(*) as total_transaksi,
        COALESCE(SUM(CASE WHEN status = 'success' THEN amount ELSE 0 END), 0) as total_nominal,
        COUNT(CASE WHEN status = 'success' THEN 1 END) as berhasil,
        COUNT(CASE WHEN status != 'success' THEN 1 END) as gagal,
        COUNT(DISTINCT user_id) as unique_customer
      FROM topup_transactions
      WHERE merchant_id = ?
        AND MONTH(created_at) = ?
        AND YEAR(created_at) = ?
    `, [merchantId, month, year]);

    // Daftar tahun yang ada transaksinya (untuk dropdown)
    const [years] = await db.query(`
      SELECT DISTINCT YEAR(created_at) as y
      FROM topup_transactions
      WHERE merchant_id = ?
      ORDER BY y DESC
    `, [merchantId]);

    const availableYears = years.map(r => r.y);
    if (!availableYears.includes(now.getFullYear())) {
      availableYears.unshift(now.getFullYear());
    }

    res.render('estatement', {
      title: 'E-Statement - DogiPay',
      merchant: req.session.merchant,
      success: req.flash('success'),
      error: req.flash('error'),
      transactions,
      summary: summary[0],
      selectedMonth: month,
      selectedYear: year,
      availableYears
    });

  } catch (err) {
    console.error(err);
    res.render('estatement', {
      title: 'E-Statement - DogiPay',
      merchant: req.session.merchant,
      success: [], error: ['Gagal memuat data'],
      transactions: [], summary: {},
      selectedMonth: new Date().getMonth() + 1,
      selectedYear: new Date().getFullYear(),
      availableYears: [new Date().getFullYear()]
    });
  }
});

module.exports = router;