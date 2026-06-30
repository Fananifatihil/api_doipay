const express = require('express');
const router = express.Router();
const { db } = require('../config/db');
const { isAuthenticated } = require('../middleware/auth');

// GET /dashboard
router.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const merchantId = req.session.merchant.id;

    // Total top-up hari ini
    const [todayTopup] = await db.query(`
      SELECT COALESCE(SUM(amount), 0) as total, COUNT(*) as count
      FROM topup_transactions
      WHERE merchant_id = ? AND DATE(created_at) = CURDATE() AND status = 'success'
    `, [merchantId]);

    // Total customer aktif
    const [activeUsers] = await db.query(`
      SELECT COUNT(*) as count FROM users WHERE is_active = 1
    `);

    // Total top-up bulan ini
    const [monthTopup] = await db.query(`
      SELECT COALESCE(SUM(amount), 0) as total, COUNT(*) as count
      FROM topup_transactions
      WHERE merchant_id = ? AND MONTH(created_at) = MONTH(CURDATE()) AND status = 'success'
    `, [merchantId]);

    // Transaksi terbaru (10 terakhir)
    const [recentTransactions] = await db.query(`
      SELECT t.*, u.name as customer_name, u.phone as customer_phone
      FROM topup_transactions t
      JOIN users u ON t.user_id = u.id
      WHERE t.merchant_id = ?
      ORDER BY t.created_at DESC
      LIMIT 10
    `, [merchantId]);


    // Grafik top-up 7 hari terakhir
    const [chartDaily] = await db.query(`
      SELECT 
        DATE(created_at) as tanggal,
        COALESCE(SUM(amount), 0) as total,
        COUNT(*) as jumlah
      FROM topup_transactions
      WHERE merchant_id = ? 
        AND status = 'success'
        AND created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
      GROUP BY DATE(created_at)
      ORDER BY tanggal ASC
    `, [merchantId]);

    // Grafik top-up per jam hari ini
    const [chartHourly] = await db.query(`
      SELECT 
        HOUR(created_at) as jam,
        COALESCE(SUM(amount), 0) as total,
        COUNT(*) as jumlah
      FROM topup_transactions
      WHERE merchant_id = ?
        AND status = 'success'
        AND DATE(created_at) = CURDATE()
      GROUP BY HOUR(created_at)
      ORDER BY jam ASC
    `, [merchantId]);

    // Buat array 7 hari lengkap (isi 0 kalau tidak ada transaksi)
    const last7Days = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const key = d.toISOString().split('T')[0];
      const label = d.toLocaleDateString('id-ID', { weekday: 'short', day: 'numeric', month: 'short' });
      const found = chartDaily.find(r => r.tanggal.toISOString().split('T')[0] === key);
      last7Days.push({ label, total: found ? Number(found.total) : 0, jumlah: found ? found.jumlah : 0 });
    }

    // Buat array 24 jam lengkap
    const hours24 = [];
    for (let h = 0; h < 24; h++) {
      const found = chartHourly.find(r => r.jam === h);
      hours24.push({ label: `${String(h).padStart(2,'0')}:00`, total: found ? Number(found.total) : 0, jumlah: found ? found.jumlah : 0 });
    }

    res.render('dashboard', {
      title: 'Dashboard - DogiPay',
      merchant: req.session.merchant,
      success: req.flash('success'),
      error: req.flash('error'),
      stats: {
        todayTotal: todayTopup[0].total,
        todayCount: todayTopup[0].count,
        activeUsers: activeUsers[0].count,
        monthTotal: monthTopup[0].total,
        monthCount: monthTopup[0].count,
      },
      recentTransactions,
      chartWeekly: JSON.stringify(last7Days),   
      chartToday: JSON.stringify(hours24)  
    });
  } catch (err) {
    console.error(err);
    res.render('dashboard', {
      title: 'Dashboard - DogiPay',
      merchant: req.session.merchant,
      success: [],
      error: ['Gagal memuat data'],
      stats: { todayTotal: 0, todayCount: 0, activeUsers: 0, monthTotal: 0, monthCount: 0 },
      recentTransactions: [],
      chartWeekly: JSON.stringify([]),
      chartToday: JSON.stringify([])
    });
  }
});

module.exports = router;
