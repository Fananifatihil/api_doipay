const express = require('express');
const router = express.Router();
const { db } = require('../config/db');
const { isAuthenticated } = require('../middleware/auth');
const { emitTopupSuccess } = require('./topup-events');

// GET /topup - halaman isi saldo
router.get('/topup', isAuthenticated, (req, res) => {
  res.render('topup', {
    title: 'Isi Saldo - DogiPay',
    merchant: req.session.merchant,
    success: req.flash('success'),
    error: req.flash('error'),
    customer: null,
    prefillAmount: 0
  });
});

// POST /topup/cek - cek customer by phone atau qr_code
router.post('/topup/cek', isAuthenticated, async (req, res) => {
  const { phone_or_qr, prefill_amount } = req.body;
  try {
    const [rows] = await db.query(
      'SELECT id, name, phone, saldo FROM users WHERE (phone = ? OR qr_code = ?) AND is_active = 1',
      [phone_or_qr, phone_or_qr]
    );

    if (rows.length === 0) {
      req.flash('error', 'Customer tidak ditemukan');
      return res.redirect('/topup');
    }

    res.render('topup', {
      title: 'Isi Saldo - DogiPay',
      merchant: req.session.merchant,
      success: req.flash('success'),
      error: req.flash('error'),
      customer: rows[0],
      prefillAmount: parseFloat(prefill_amount) || 0  // ← nominal dari QR
    });
  } catch (err) {
    console.error(err);
    req.flash('error', 'Terjadi kesalahan server');
    res.redirect('/topup');
  }
});

// POST /topup/proses - proses top-up saldo
router.post('/topup/proses', isAuthenticated, async (req, res) => {
  const { user_id, amount, note } = req.body;
  const merchantId = req.session.merchant.id;
  const nominalAmount = parseFloat(amount);

  if (!nominalAmount || nominalAmount <= 0) {
    req.flash('error', 'Nominal tidak valid');
    return res.redirect('/topup');
  }

  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    const [userRows] = await conn.query('SELECT id, name, saldo FROM users WHERE id = ? FOR UPDATE', [user_id]);
    if (userRows.length === 0) throw new Error('Customer tidak ditemukan');

    const user = userRows[0];
    const saldoBefore = parseFloat(user.saldo);
    const saldoAfter = saldoBefore + nominalAmount;

    await conn.query('UPDATE users SET saldo = ? WHERE id = ?', [saldoAfter, user_id]);

    const [topupResult] = await conn.query(`
        INSERT INTO topup_transactions (merchant_id, user_id, amount, saldo_before, saldo_after, note, status)
        VALUES (?, ?, ?, ?, ?, ?, 'success')
    `, [merchantId, user_id, nominalAmount, saldoBefore, saldoAfter, note || null]);

    await conn.query(`
        INSERT INTO notifications (user_id, title, message, type, reference_id)
        VALUES (?, 'Saldo Masuk', ?, 'topup', ?)
    `, [user_id, `Saldo kamu berhasil diisi sebesar Rp ${nominalAmount.toLocaleString('id-ID')}`, topupResult.insertId]);
    await conn.commit();

    emitTopupSuccess({
      userId: user_id,
      merchantId,
      amount: nominalAmount,
      saldoBefore,
      saldoAfter
    });

    req.flash('success', `Berhasil top-up Rp ${nominalAmount.toLocaleString('id-ID')} ke ${user.name}`);
    res.redirect('/dashboard');
  } catch (err) {
    await conn.rollback();
    console.error(err);
    req.flash('error', 'Gagal memproses top-up');
    res.redirect('/topup');
  } finally {
    conn.release();
  }
});

module.exports = router;