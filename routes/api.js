const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { addTopupClient, emitTopupSuccess, emitTransferSuccess } = require('./topup-events');

// ==========================================
// 1. KONFIGURASI DATABASE
// ==========================================
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    timezone: '+07:00'
});

const notificationClients = new Map();
const JWT_SECRET = process.env.SESSION_SECRET || 'dogipay_rahasia_super_aman';

// ==========================================
// HELPER: Format waktu WIB untuk notifikasi
// ==========================================
const formatWIB = (date = new Date()) => {
    const wibOffset = 7 * 60 * 60 * 1000;
    const wib = new Date(date.getTime() + wibOffset);
    const bulan = ['Jan','Feb','Mar','Apr','Mei','Jun','Jul','Agu','Sep','Okt','Nov','Des'];
    const tgl = wib.getUTCDate() + ' ' + bulan[wib.getUTCMonth()] + ' ' + wib.getUTCFullYear();
    const jam = ('0' + wib.getUTCHours()).slice(-2) + ':' + ('0' + wib.getUTCMinutes()).slice(-2);
    return { tgl, jam, label: `${tgl} ${jam}` };
};

// ==========================================
// 2. MIDDLEWARE KEAMANAN (JWT & STATUS)
// ==========================================
const verifyTokenAndStatus = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const bearerToken = authHeader && authHeader.split(' ')[1];
        const token = bearerToken || req.query.token;

        if (!token) {
            return res.status(401).json({ success: false, message: "Akses ditolak. Sesi tidak ditemukan." });
        }

        jwt.verify(token, JWT_SECRET, async (err, decoded) => {
            try {
                if (err) {
                    if (!res.headersSent) {
                        return res.status(403).json({ success: false, message: "Sesi telah berakhir. Silakan login kembali." });
                    }
                    return;
                }

                const userId = decoded.id;
                const [rows] = await pool.query('SELECT is_active FROM users WHERE id = ? LIMIT 1', [userId]);

                if (rows.length === 0 || rows[0].is_active !== 1) {
                    if (!res.headersSent) {
                        return res.status(403).json({ success: false, message: "Akses ditolak. Akun Anda sedang ditangguhkan." });
                    }
                    return;
                }

                req.user = decoded;
                next();
            } catch (innerError) {
                console.error("Error verifyTokenAndStatus (inner):", innerError.message);
                if (!res.headersSent) {
                    res.status(500).json({ success: false, message: "Gagal memverifikasi keamanan." });
                }
            }
        });
    } catch (error) {
        if (!res.headersSent) {
            return res.status(500).json({ success: false, message: "Gagal memverifikasi keamanan." });
        }
    }
};

// ==========================================
// 3. ENDPOINT API
// ==========================================

// A. Health Check
router.get('/status', (req, res) => {
    res.status(200).json({
        success: true,
        message: "API Mobile DogiPay berjalan sempurna dengan JWT!",
        timestamp: new Date().toISOString()
    });
});

// B. Register
router.post('/register', async (req, res) => {
    try {
        const { name, email, phone, pin } = req.body;

        if (!name || !email || !phone || !pin) {
            return res.status(400).json({ success: false, message: "Semua kolom wajib diisi." });
        }

        if (!/^\d{6}$/.test(pin)) {
            return res.status(400).json({ success: false, message: "PIN harus berupa 6 digit angka." });
        }

        const [existingUser] = await pool.query(
            'SELECT id FROM users WHERE phone = ? OR email = ? LIMIT 1',
            [phone, email]
        );

        if (existingUser.length > 0) {
            return res.status(400).json({ success: false, message: "Nomor HP atau Email sudah terdaftar." });
        }

        const saltRounds = 10;
        const hashedPin = await bcrypt.hash(pin, saltRounds);
        const qrCode = `QR-USER-${Date.now()}-${phone.substring(phone.length - 4)}`;

        const [result] = await pool.query(
            'INSERT INTO users (name, email, password, pin, phone, qr_code, saldo, is_active, tabungan) VALUES (?, ?, ?, ?, ?, ?, 0.00, 1, 0.00)',
            [name, email, hashedPin, hashedPin, phone, qrCode]
        );

        res.status(201).json({
            success: true,
            message: "Pendaftaran berhasil! Silakan login dengan Nomor HP dan PIN Anda.",
            data: { id: result.insertId, name: name, phone: phone }
        });

    } catch (error) {
        console.error("Error Register:", error.message);
        res.status(500).json({
            success: false,
            message: "Kesalahan internal server saat mendaftar",
            error_detail: error.message
        });
    }
});

// C. Login
router.post('/login', async (req, res) => {
    try {
        const { phone, pin, device_name } = req.body;

        if (!phone || !pin) return res.status(400).json({ success: false, message: "Harap isi Nomor HP dan PIN" });

        const [rows] = await pool.query('SELECT * FROM users WHERE phone = ? LIMIT 1', [phone]);

        if (rows.length === 0) return res.status(401).json({ success: false, message: "Nomor HP tidak terdaftar" });

        const user = rows[0];

        if (user.is_active !== 1) return res.status(403).json({ success: false, message: "Login gagal. Akun Anda tidak aktif." });

        const match = await bcrypt.compare(pin, user.password);
        if (!match) return res.status(401).json({ success: false, message: "PIN salah" });

        const accessToken = jwt.sign(
            { id: user.id, phone: user.phone },
            process.env.SESSION_SECRET || 'dogipay_rahasia_super_aman',
            { expiresIn: '7d' }
        );

        try {
            const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
            await pool.query(
                'INSERT INTO user_sessions (user_id, token, device_name, ip_address) VALUES (?, ?, ?, ?)',
                [user.id, accessToken, device_name || 'Browser/Unknown Device', ipAddress]
            );
        } catch (sessionErr) {
            console.error("Gagal mencatat sesi perangkat:", sessionErr.message);
        }

        res.status(200).json({
            success: true,
            message: "Login berhasil",
            token: accessToken,
            data: {
                id: user.id,
                name: user.name,
                phone: user.phone,
                qr_code: user.qr_code,
                saldo: user.saldo,
                tabungan: user.tabungan || 0
            }
        });
    } catch (error) {
        console.error("Error Login:", error);
        res.status(500).json({ success: false, message: "Kesalahan internal server" });
    }
});

// D. Profil
router.get('/profile', verifyTokenAndStatus, async (req, res) => {
    try {
        const userId = req.user.id;
        const [rows] = await pool.query('SELECT id, name, phone, qr_code, saldo, tabungan FROM users WHERE id = ?', [userId]);

        if (rows.length === 0) return res.status(404).json({ success: false, message: "User tidak ditemukan" });

        res.status(200).json({ success: true, data: rows[0] });
    } catch (error) {
        res.status(500).json({ success: false, message: "Gagal memuat profil" });
    }
});

router.put('/profile', verifyTokenAndStatus, async (req, res) => {
    try {
        const userId = req.user.id;
        const { name, email } = req.body;
        if (!name) {
            return res.status(400).json({ success: false, message: "Nama tidak boleh kosong." });
        }
        await pool.query(
            'UPDATE users SET name = ?, email = ? WHERE id = ?',
            [name, email || null, userId]
        );
        const [rows] = await pool.query(
            'SELECT id, name, phone, qr_code, saldo, tabungan, email FROM users WHERE id = ? LIMIT 1', 
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "User tidak ditemukan" });
        }

        res.status(200).json({
            success: true,
            message: "Profil berhasil diperbarui!",
            data: rows[0]
        });

    } catch (error) {
        console.error("Error Update Profile:", error.message);
        res.status(500).json({ success: false, message: "Gagal memperbarui profil" });
    }
});

// D3. SSE Realtime
router.get('/topup-events', verifyTokenAndStatus, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    const removeClient = addTopupClient(req.user.id, res);
    const heartbeat = setInterval(() => {
        res.write(`event: ping\n`);
        res.write(`data: {"timestamp":"${new Date().toISOString()}"}\n\n`);
    }, 30000);

    req.on('close', () => {
        clearInterval(heartbeat);
        removeClient();
    });
});

// E. Top Up
router.post('/topup', verifyTokenAndStatus, async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const userId = req.user.id;
        const { merchantId, amount } = req.body;

        if (!amount || amount <= 0) return res.status(400).json({ success: false, message: "Nominal tidak valid" });

        await connection.beginTransaction();

        const [users] = await connection.query('SELECT saldo FROM users WHERE id = ? FOR UPDATE', [userId]);
        if (users.length === 0) throw new Error("User tidak ditemukan");

        const saldoBefore = parseFloat(users[0].saldo);
        const saldoAfter = saldoBefore + parseFloat(amount);

        await connection.query('UPDATE users SET saldo = ? WHERE id = ?', [saldoAfter, userId]);

        const [topupResult] = await connection.query(
            'INSERT INTO topup_transactions (merchant_id, user_id, amount, saldo_before, saldo_after, status) VALUES (?, ?, ?, ?, ?, ?)',
            [merchantId || 1, userId, amount, saldoBefore, saldoAfter, 'success']
        );

        await connection.query(
            'INSERT INTO notifications (user_id, title, message, type, reference_id) VALUES (?, ?, ?, ?, ?)',
            [userId, 'Saldo Masuk', `Saldo kamu berhasil diisi sebesar Rp ${Number(amount).toLocaleString('id-ID')}`, 'topup', topupResult.insertId]
        );

        await connection.commit();

        emitTopupSuccess({
            userId,
            merchantId: merchantId || 1,
            amount: parseFloat(amount),
            saldoBefore,
            saldoAfter
        });

        res.status(200).json({ success: true, message: `Top up Rp ${amount} berhasil`, saldo: saldoAfter });
    } catch (error) {
        await connection.rollback();
        res.status(400).json({ success: false, message: error.message || "Top up gagal" });
    } finally {
        connection.release();
    }
});

// F. Transfer
router.post('/transfer', verifyTokenAndStatus, async (req, res) => {
    const connection = await pool.getConnection();

    try {
        const { receiverPhone, amount, catatan, requestCode, pin } = req.body;
        const senderId = req.user.id;
        let cleanAmount = parseFloat(amount);
        let cleanCatatan = catatan || null;
        let finalReceiverPhone = receiverPhone;
        let transferRequest = null;

        if (!requestCode && !receiverPhone) {
            connection.release();
            return res.status(400).json({ success: false, message: "Nomor HP penerima wajib diisi." });
        }

        await connection.beginTransaction();

        if (requestCode) {
            const [reqRows] = await connection.query(
                `SELECT tr.*, u.phone AS requester_phone, u.name AS requester_name
                 FROM transfer_requests tr
                 JOIN users u ON u.id = tr.requester_id
                 WHERE tr.request_code = ? FOR UPDATE`,
                [requestCode]
            );

            if (!reqRows || reqRows.length === 0) {
                await connection.rollback();
                return res.status(404).json({ success: false, message: "QR Code permintaan transfer tidak ditemukan." });
            }
            transferRequest = reqRows[0];

            if (transferRequest.status === 'paid') {
                await connection.rollback();
                return res.status(409).json({ success: false, message: "QR Code ini sudah digunakan untuk transfer sebelumnya." });
            }
            if (transferRequest.status === 'cancelled') {
                await connection.rollback();
                return res.status(410).json({ success: false, message: "Permintaan transfer ini sudah dibatalkan." });
            }
            if (transferRequest.status !== 'pending' || new Date(transferRequest.expires_at) < new Date()) {
                await connection.query(
                    `UPDATE transfer_requests SET status = 'expired' WHERE id = ? AND status = 'pending'`,
                    [transferRequest.id]
                );
                await connection.commit();
                return res.status(410).json({ success: false, message: "QR Code sudah kedaluwarsa. Minta pengirim untuk membuat QR baru." });
            }

            cleanAmount = parseFloat(transferRequest.amount);
            cleanCatatan = transferRequest.catatan;
            finalReceiverPhone = transferRequest.requester_phone;
        }

        if (isNaN(cleanAmount) || cleanAmount < 1000) {
            await connection.rollback();
            return res.status(400).json({ success: false, message: "Nominal transfer minimal Rp 1.000." });
        }

        const [senderRows] = await connection.query(
            'SELECT id, name, phone, saldo, password FROM users WHERE id = ? FOR UPDATE',
            [senderId]
        );

        if (!senderRows || senderRows.length === 0) {
            await connection.rollback();
            return res.status(400).json({ success: false, message: "Data pengirim tidak valid." });
        }
        const sender = senderRows[0];

        if (!pin) {
            await connection.rollback();
            return res.status(400).json({ success: false, message: "PIN wajib diisi." });
        }

        const match = await bcrypt.compare(pin, sender.password);

        if (!match) {
            await connection.rollback();
            return res.status(401).json({ success: false, message: "PIN salah." });
        }

        if (String(sender.phone) === String(finalReceiverPhone).trim()) {
            await connection.rollback();
            return res.status(400).json({ success: false, message: "Tidak bisa transfer ke nomor sendiri." });
        }

        const senderSaldoBefore = parseFloat(sender.saldo);
        if (senderSaldoBefore < cleanAmount) {
            await connection.rollback();
            return res.status(400).json({ success: false, message: "Saldo Anda tidak mencukupi." });
        }

        const [receiverRows] = await connection.query(
            'SELECT id, name, phone, saldo FROM users WHERE phone = ? FOR UPDATE',
            [String(finalReceiverPhone).trim()]
        );

        if (!receiverRows || receiverRows.length === 0) {
            await connection.rollback();
            return res.status(404).json({ success: false, message: "Nomor HP penerima tidak terdaftar di DogiPay." });
        }
        const receiver = receiverRows[0];

        const senderSaldoAfter    = senderSaldoBefore - cleanAmount;
        const receiverSaldoBefore = parseFloat(receiver.saldo);
        const receiverSaldoAfter  = receiverSaldoBefore + cleanAmount;

        await connection.query('UPDATE users SET saldo = ? WHERE id = ?', [senderSaldoAfter, senderId]);
        await connection.query('UPDATE users SET saldo = ? WHERE id = ?', [receiverSaldoAfter, receiver.id]);

        const [trxResult] = await connection.query(
            `INSERT INTO transfer_transactions 
            (sender_id, receiver_id, amount, saldo_before_sender, saldo_after_sender, saldo_before_receiver, saldo_after_receiver, note, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'success')`,
            [senderId, receiver.id, cleanAmount, senderSaldoBefore, senderSaldoAfter, receiverSaldoBefore, receiverSaldoAfter, cleanCatatan]
        );

        if (transferRequest) {
            await connection.query(
                `UPDATE transfer_requests 
                 SET status = 'paid', sender_id = ?, transfer_transaction_id = ?, paid_at = NOW() 
                 WHERE id = ? AND status = 'pending'`,
                [senderId, trxResult.insertId, transferRequest.id]
            );
        }

        // ==========================================
        // NOTIFIKASI FORMAT REALTIME TRANSFER
        // ==========================================
        const { tgl, jam } = formatWIB();
        const nominalFmt = cleanAmount.toLocaleString('id-ID');

        await connection.query(
            'INSERT INTO notifications (user_id, title, message, type, reference_id) VALUES (?, ?, ?, ?, ?)',
            [
                senderId,
                'Realtime Transfer',
                `Kamu baru melakukan transfer senilai Rp${nominalFmt} kepada ${receiver.name} pada ${tgl} ${jam} (WIB). Jika kamu tidak melakukan ini, segera hubungi 1500130.`,
                'transfer_out',
                trxResult.insertId
            ]
        );

        await connection.query(
            'INSERT INTO notifications (user_id, title, message, type, reference_id) VALUES (?, ?, ?, ?, ?)',
            [
                receiver.id,
                'Realtime Transfer',
                `Kamu baru menerima transfer senilai Rp${nominalFmt} dari ${sender.name} pada ${tgl} ${jam} (WIB). Jika kamu tidak merasa menerima ini, segera hubungi 1500130.`,
                'transfer_in',
                trxResult.insertId
            ]
        );

        await connection.commit();

        emitTransferSuccess({
            senderId,
            receiverId: receiver.id,
            senderName: sender.name,
            receiverName: receiver.name,
            amount: cleanAmount,
            senderSaldoAfter,
            receiverSaldoAfter
        });

        return res.status(200).json({
            success: true,
            message: "Transfer berhasil",
            data: {
                senderName: sender.name,
                receiverName: receiver.name,
                amount: cleanAmount,
                saldoTerbaru: senderSaldoAfter
            }
        });

    } catch (error) {
        await connection.rollback();
        console.error("CRITICAL_ERROR_TRANSFER:", error.message);
        return res.status(500).json({
            success: false,
            message: "Terjadi kesalahan internal server.",
            debug_message: error.message
        });
    } finally {
        connection.release();
    }
});

// F2.1 Buat Transfer Request
router.post('/transfer-request', verifyTokenAndStatus, async (req, res) => {
    try {
        const requesterId = req.user.id;
        const { amount, catatan } = req.body;
        const cleanAmount = parseFloat(amount);

        if (isNaN(cleanAmount) || cleanAmount < 1000) {
            return res.status(400).json({ success: false, message: "Nominal minimal Rp 1.000." });
        }

        const requestCode = 'TRX' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(6).toString('hex').toUpperCase();
        const expiresAt = new Date(Date.now() + 3 * 60 * 1000);

        await pool.query(
            `INSERT INTO transfer_requests (request_code, requester_id, amount, catatan, status, expires_at) 
             VALUES (?, ?, ?, ?, 'pending', ?)`,
            [requestCode, requesterId, cleanAmount, catatan || null, expiresAt]
        );

        const [userRows] = await pool.query('SELECT name, phone FROM users WHERE id = ?', [requesterId]);
        const requester = userRows[0] || {};

        res.status(201).json({
            success: true,
            message: "Permintaan transfer berhasil dibuat",
            data: {
                requestCode,
                amount: cleanAmount,
                catatan: catatan || null,
                expiresAt,
                requesterName: requester.name,
                requesterPhone: requester.phone
            }
        });
    } catch (error) {
        console.error("Error Create Transfer Request:", error.message);
        res.status(500).json({ success: false, message: "Gagal membuat permintaan transfer." });
    }
});

// F2.2 Cek Status Transfer Request
router.get('/transfer-request/:code', verifyTokenAndStatus, async (req, res) => {
    try {
        const { code } = req.params;
        const [rows] = await pool.query(
            `SELECT tr.*, s.name AS sender_name 
             FROM transfer_requests tr
             LEFT JOIN users s ON s.id = tr.sender_id
             WHERE tr.request_code = ? AND tr.requester_id = ? LIMIT 1`,
            [code, req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "Permintaan transfer tidak ditemukan." });
        }

        const reqRow = rows[0];

        if (reqRow.status === 'pending' && new Date(reqRow.expires_at) < new Date()) {
            await pool.query(`UPDATE transfer_requests SET status = 'expired' WHERE id = ? AND status = 'pending'`, [reqRow.id]);
            reqRow.status = 'expired';
        }

        res.status(200).json({
            success: true,
            data: {
                requestCode: reqRow.request_code,
                status: reqRow.status,
                amount: parseFloat(reqRow.amount),
                catatan: reqRow.catatan,
                senderName: reqRow.sender_name,
                paidAt: reqRow.paid_at,
                expiresAt: reqRow.expires_at
            }
        });
    } catch (error) {
        console.error("Error Check Transfer Request:", error.message);
        res.status(500).json({ success: false, message: "Gagal memeriksa status permintaan transfer." });
    }
});

// F2.3 Batalkan Transfer Request
router.post('/transfer-request/:code/cancel', verifyTokenAndStatus, async (req, res) => {
    try {
        const { code } = req.params;
        const [result] = await pool.query(
            `UPDATE transfer_requests SET status = 'cancelled' 
             WHERE request_code = ? AND requester_id = ? AND status = 'pending'`,
            [code, req.user.id]
        );

        if (result.affectedRows === 0) {
            return res.status(400).json({ success: false, message: "Permintaan tidak dapat dibatalkan (mungkin sudah dibayar/kedaluwarsa)." });
        }

        res.status(200).json({ success: true, message: "Permintaan transfer dibatalkan." });
    } catch (error) {
        console.error("Error Cancel Transfer Request:", error.message);
        res.status(500).json({ success: false, message: "Gagal membatalkan permintaan transfer." });
    }
});

// F2.4 Lookup QR Code
router.get('/lookup-qr/:code', verifyTokenAndStatus, async (req, res) => {
    try {
        const { code } = req.params;

        const [rows] = await pool.query(
            `SELECT tr.*, u.name AS requester_name, u.phone AS requester_phone 
             FROM transfer_requests tr
             JOIN users u ON u.id = tr.requester_id
             WHERE tr.request_code = ? LIMIT 1`,
            [code]
        );

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "QR Code tidak ditemukan." });
        }

        const data = rows[0];

        if (data.status !== 'pending') {
            return res.status(400).json({ success: false, message: "QR Code sudah tidak berlaku." });
        }

        if (new Date(data.expires_at) < new Date()) {
            await pool.query(`UPDATE transfer_requests SET status = 'expired' WHERE id = ?`, [data.id]);
            return res.status(410).json({ success: false, message: "QR Code sudah kedaluwarsa." });
        }

        res.status(200).json({
            success: true,
            data: {
                requestCode: data.request_code,
                amount: parseFloat(data.amount),
                catatan: data.catatan,
                requesterName: data.requester_name,
                requesterPhone: data.requester_phone
            }
        });
    } catch (error) {
        console.error("Error Lookup QR:", error.message);
        res.status(500).json({ success: false, message: "Terjadi kesalahan pada server." });
    }
});

// G. Savings (endpoint lama)
router.post('/savings', verifyTokenAndStatus, async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const userId = req.user.id;
        const { amount } = req.body;

        if (!amount || amount <= 0) return res.status(400).json({ success: false, message: "Nominal tidak valid" });

        await connection.beginTransaction();

        const [users] = await connection.query('SELECT saldo, tabungan FROM users WHERE id = ? FOR UPDATE', [userId]);
        if (users.length === 0) throw new Error("User tidak ditemukan");

        const user = users[0];
        if (parseFloat(user.saldo) < amount) throw new Error("Saldo utama tidak mencukupi untuk menabung");

        const saldoAfter = parseFloat(user.saldo) - parseFloat(amount);
        const tabunganAfter = parseFloat(user.tabungan) + parseFloat(amount);

        await connection.query('UPDATE users SET saldo = ?, tabungan = ? WHERE id = ?', [saldoAfter, tabunganAfter, userId]);

        await connection.query(
            'INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)',
            [userId, 'Tabungan', `Berhasil memindahkan Rp ${amount} ke tabungan`, 'system']
        );

        await connection.commit();
        res.status(200).json({ success: true, message: "Berhasil menabung", saldo: saldoAfter, tabungan: tabunganAfter });
    } catch (error) {
        await connection.rollback();
        res.status(400).json({ success: false, message: error.message || "Gagal memproses tabungan" });
    } finally {
        connection.release();
    }
});

// ==========================================
// H. RIWAYAT TRANSAKSI
// Hanya menampilkan keluar/masuk uang:
// topup, transfer_in, transfer_out, system
// ==========================================
router.get('/history', verifyTokenAndStatus, async (req, res) => {
    try {
        const userId = req.user.id;
        const { type, date_from, date_to } = req.query;

        // Batasi hanya tipe transaksi keuangan, TIDAK termasuk system/promo
        let whereClause = `WHERE n.user_id = ?`;
        const params = [userId];

        if (type && ['topup', 'transfer_in', 'transfer_out', 'system'].includes(type)) {
            whereClause += ' AND n.type = ?';
            params.push(type);
        } else {
            whereClause += ` AND n.type IN ('topup', 'transfer_in', 'transfer_out', 'system')`;
        }

        if (date_from) {
            whereClause += ' AND DATE(n.created_at) >= ?';
            params.push(date_from);
        }

        if (date_to) {
            whereClause += ' AND DATE(n.created_at) <= ?';
            params.push(date_to);
        }

        const [notifications] = await pool.query(`
            SELECT n.id, n.title, n.message, n.type, n.reference_id, n.created_at
            FROM notifications n
            ${whereClause}
            ORDER BY n.created_at DESC
            LIMIT 100
        `, params);

        const result = await Promise.all(notifications.map(async (notif) => {
            let amount = null;
            let detail = {};

            if (notif.type === 'topup' && notif.reference_id) {
                const [rows] = await pool.query(`
                    SELECT t.amount, t.saldo_before, t.saldo_after, t.note, t.status,
                           t.created_at AS trx_date, m.name AS merchant_name
                    FROM topup_transactions t
                    LEFT JOIN merchants m ON m.id = t.merchant_id
                    WHERE t.id = ? LIMIT 1
                `, [notif.reference_id]);
                if (rows[0]) {
                    amount = rows[0].amount;
                    detail = {
                        merchantName: rows[0].merchant_name || 'Merchant',
                        saldoBefore: rows[0].saldo_before,
                        saldoAfter: rows[0].saldo_after,
                        note: rows[0].note,
                        status: rows[0].status,
                        trxDate: rows[0].trx_date,
                    };
                }
            }

            if (notif.type === 'transfer_out' && notif.reference_id) {
                const [rows] = await pool.query(`
                    SELECT t.amount, t.note, t.status, t.created_at AS trx_date,
                           t.saldo_before_sender AS saldo_before, t.saldo_after_sender AS saldo_after,
                           r.name AS receiver_name, r.phone AS receiver_phone,
                           s.name AS sender_name, s.phone AS sender_phone
                    FROM transfer_transactions t
                    LEFT JOIN users r ON r.id = t.receiver_id
                    LEFT JOIN users s ON s.id = t.sender_id
                    WHERE t.id = ? LIMIT 1
                `, [notif.reference_id]);
                if (rows[0]) {
                    amount = rows[0].amount;
                    detail = {
                        senderName: rows[0].sender_name,
                        senderPhone: rows[0].sender_phone,
                        receiverName: rows[0].receiver_name,
                        receiverPhone: rows[0].receiver_phone,
                        saldoBefore: rows[0].saldo_before,
                        saldoAfter: rows[0].saldo_after,
                        note: rows[0].note,
                        status: rows[0].status,
                        trxDate: rows[0].trx_date,
                    };
                }
            }

            if (notif.type === 'transfer_in' && notif.reference_id) {
                const [rows] = await pool.query(`
                    SELECT t.amount, t.note, t.status, t.created_at AS trx_date,
                           t.saldo_before_receiver AS saldo_before, t.saldo_after_receiver AS saldo_after,
                           s.name AS sender_name, s.phone AS sender_phone,
                           r.name AS receiver_name, r.phone AS receiver_phone
                    FROM transfer_transactions t
                    LEFT JOIN users s ON s.id = t.sender_id
                    LEFT JOIN users r ON r.id = t.receiver_id
                    WHERE t.id = ? LIMIT 1
                `, [notif.reference_id]);
                if (rows[0]) {
                    amount = rows[0].amount;
                    detail = {
                        senderName: rows[0].sender_name,
                        senderPhone: rows[0].sender_phone,
                        receiverName: rows[0].receiver_name,
                        receiverPhone: rows[0].receiver_phone,
                        saldoBefore: rows[0].saldo_before,
                        saldoAfter: rows[0].saldo_after,
                        note: rows[0].note,
                        status: rows[0].status,
                        trxDate: rows[0].trx_date,
                    };
                }
            }

            // Fallback parse nominal dari message jika reference_id NULL (data lama)
            if (!amount) {
                const match = notif.message.match(/Rp[\s.]?([\d.]+)/);
                if (match) amount = parseFloat(match[1].replace(/\./g, ''));
            }

            return { ...notif, amount, detail };
        }));

        res.status(200).json({ success: true, data: result });

    } catch (error) {
        console.error('ERROR /history:', error.message);
        res.status(500).json({ success: false, message: "Gagal memuat riwayat transaksi" });
    }
});

// ==========================================
// TABUNGAN - GET status tabungan aktif
// ==========================================
router.get('/tabungan', verifyTokenAndStatus, async (req, res) => {
    try {
        const userId = req.user.id;
        const [rows] = await pool.query(
            `SELECT tabungan, tabungan_nama, tabungan_target, tabungan_total_cicilan,
                    tabungan_cicilan_sudah, tabungan_per_periode, tabungan_frekuensi,
                    tabungan_status, tabungan_next_due_at
             FROM users WHERE id = ? LIMIT 1`,
            [userId]
        );

        if (rows.length === 0) return res.status(404).json({ success: false, message: 'User tidak ditemukan' });

        const u = rows[0];

        if (!u.tabungan_status || u.tabungan_status === 'none') {
            return res.status(200).json({ success: true, data: null });
        }

        res.status(200).json({
            success: true,
            data: {
                terkumpul: parseFloat(u.tabungan) || 0,
                nama: u.tabungan_nama,
                target: parseFloat(u.tabungan_target),
                totalCicilan: u.tabungan_total_cicilan,
                cicilansudah: u.tabungan_cicilan_sudah,
                cicilanPerPeriode: parseFloat(u.tabungan_per_periode),
                frekuensi: u.tabungan_frekuensi,
                status: u.tabungan_status,
                nextDueAt: u.tabungan_next_due_at
            }
        });
    } catch (error) {
        console.error('Error GET tabungan:', error.message);
        res.status(500).json({ success: false, message: 'Gagal memuat data tabungan' });
    }
});

// ==========================================
// TABUNGAN - Buat rencana tabungan baru
// ==========================================
router.post('/tabungan', verifyTokenAndStatus, async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const userId = req.user.id;
        const { nama, target, totalCicilan, frekuensi } = req.body;

        if (!nama || !target || !totalCicilan || !frekuensi) {
            return res.status(400).json({ success: false, message: 'Semua field wajib diisi' });
        }

        if (target < 10000) return res.status(400).json({ success: false, message: 'Target minimal Rp 10.000' });
        if (totalCicilan < 1) return res.status(400).json({ success: false, message: 'Cicilan minimal 1 kali' });

        const validFrekuensi = ['daily', 'weekly', 'monthly', 'yearly'];
        if (!validFrekuensi.includes(frekuensi)) {
            return res.status(400).json({ success: false, message: 'Frekuensi tidak valid' });
        }

        await connection.beginTransaction();

        const [existing] = await connection.query(
            `SELECT tabungan_status FROM users WHERE id = ? FOR UPDATE`,
            [userId]
        );

        if (existing[0]?.tabungan_status === 'active') {
            await connection.rollback();
            return res.status(400).json({ success: false, message: 'Sudah ada tabungan aktif. Selesaikan atau batalkan dulu.' });
        }

        const cicilanPerPeriode = Math.ceil(target / totalCicilan);

        const nextDue = new Date();
        if (frekuensi === 'daily') nextDue.setDate(nextDue.getDate() + 1);
        else if (frekuensi === 'weekly') nextDue.setDate(nextDue.getDate() + 7);
        else if (frekuensi === 'monthly') nextDue.setMonth(nextDue.getMonth() + 1);
        else if (frekuensi === 'yearly') nextDue.setFullYear(nextDue.getFullYear() + 1);

        await connection.query(
            `UPDATE users SET
                tabungan_nama = ?,
                tabungan_target = ?,
                tabungan_total_cicilan = ?,
                tabungan_cicilan_sudah = 0,
                tabungan_per_periode = ?,
                tabungan_frekuensi = ?,
                tabungan_status = 'active',
                tabungan_next_due_at = NULL
            WHERE id = ?`,
            [nama, target, totalCicilan, cicilanPerPeriode, frekuensi, userId]
        );

        await connection.query(
            'INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)',
            [userId, 'Tabungan Dibuat', `Rencana tabungan "${nama}" berhasil dibuat. Target: Rp ${Number(target).toLocaleString('id-ID')}`, 'system']
        );

        await connection.commit();
        res.status(201).json({ success: true, message: 'Rencana tabungan berhasil dibuat' });

    } catch (error) {
        await connection.rollback();
        console.error('Error POST tabungan:', error.message);
        res.status(500).json({ success: false, message: 'Gagal membuat rencana tabungan' });
    } finally {
        connection.release();
    }
});

// TABUNGAN - Setor manual
router.post('/tabungan/setor', verifyTokenAndStatus, async (req, res) => {
    const userId = req.user.id;
    const { amount } = req.body;

    if (!amount || isNaN(amount) || amount <= 0) {
        return res.status(400).json({ success: false, message: 'Nominal setor tidak valid' });
    }

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();

        const [rows] = await connection.query(
            `SELECT saldo, tabungan, tabungan_target, tabungan_total_cicilan,
                    tabungan_cicilan_sudah, tabungan_status, tabungan_nama
             FROM users WHERE id = ? FOR UPDATE`,
            [userId]
        );
        const u = rows[0];

        if (u.tabungan_status !== 'active') {
            await connection.rollback();
            return res.status(400).json({ success: false, message: 'Tidak ada tabungan aktif' });
        }

        const saldo = parseFloat(u.saldo);
        const SALDO_MIN = 50000;

        if (saldo - amount < SALDO_MIN) {
            await connection.rollback();
            return res.status(400).json({
                success: false,
                message: `Saldo tidak cukup. Minimal sisa saldo Rp 50.000 setelah setor`
            });
        }

        const saldoAfter = saldo - amount;
        const tabunganAfter = parseFloat(u.tabungan) + parseFloat(amount);
        const cicilanSudah = u.tabungan_cicilan_sudah + 1;
        const isSelesai = tabunganAfter >= parseFloat(u.tabungan_target);

        await connection.query(
            `UPDATE users SET saldo = ?, tabungan = ?, tabungan_cicilan_sudah = ?,
             tabungan_status = ? WHERE id = ?`,
            [saldoAfter, tabunganAfter, cicilanSudah, isSelesai ? 'completed' : 'active', userId]
        );

        await connection.query(
            `INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)`,
            [userId, 'Setor Tabungan', `Rp ${Number(amount).toLocaleString('id-ID')} berhasil disetor ke tabungan "${u.tabungan_nama}"`, 'system']
        );

        await connection.commit();
        res.status(200).json({
            success: true,
            message: 'Berhasil setor ke tabungan',
            saldo: saldoAfter,
            tabungan: tabunganAfter,
            isSelesai
        });
    } catch (error) {
        await connection.rollback();
        console.error('Error setor tabungan:', error.message);
        res.status(500).json({ success: false, message: 'Gagal setor ke tabungan' });
    } finally {
        connection.release();
    }
});

// TABUNGAN - Tarik saldo tabungan
router.post('/tabungan/tarik', verifyTokenAndStatus, async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const userId = req.user.id;

        await connection.beginTransaction();

        const [rows] = await connection.query(
            `SELECT saldo, tabungan, tabungan_target, tabungan_status, tabungan_nama
             FROM users WHERE id = ? FOR UPDATE`,
            [userId]
        );

        if (rows.length === 0) throw new Error('User tidak ditemukan');

        const u = rows[0];
        const tabungan = parseFloat(u.tabungan);
        const target = parseFloat(u.tabungan_target);

        if (u.tabungan_status !== 'active' && u.tabungan_status !== 'completed') {
            await connection.rollback();
            return res.status(400).json({ success: false, message: 'Tidak ada tabungan aktif' });
        }

        if (tabungan < target) {
            await connection.rollback();
            return res.status(400).json({
                success: false,
                message: `Belum bisa tarik. Tabungan saat ini Rp ${tabungan.toLocaleString('id-ID')} dari target Rp ${target.toLocaleString('id-ID')}`
            });
        }

        const saldoAfter = parseFloat(u.saldo) + tabungan;

        await connection.query(
            `UPDATE users SET
                saldo = ?, tabungan = 0, tabungan_status = 'none',
                tabungan_nama = NULL, tabungan_target = NULL, tabungan_total_cicilan = NULL,
                tabungan_cicilan_sudah = 0, tabungan_per_periode = NULL,
                tabungan_frekuensi = NULL, tabungan_next_due_at = NULL
             WHERE id = ?`,
            [saldoAfter, userId]
        );

        await connection.query(
            'INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)',
            [userId, 'Tarik Tabungan', `Rp ${tabungan.toLocaleString('id-ID')} dari tabungan "${u.tabungan_nama}" berhasil ditransfer ke saldo utama`, 'system']
        );

        await connection.commit();
        res.status(200).json({
            success: true,
            message: 'Saldo tabungan berhasil ditarik ke saldo utama',
            saldoAfter,
            tabunganDitarik: tabungan
        });

    } catch (error) {
        await connection.rollback();
        console.error('Error tarik tabungan:', error.message);
        res.status(500).json({ success: false, message: error.message || 'Gagal menarik saldo tabungan' });
    } finally {
        connection.release();
    }
});

// TABUNGAN - Batalkan tabungan
router.post('/tabungan/batalkan', verifyTokenAndStatus, async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const userId = req.user.id;

        await connection.beginTransaction();

        const [rows] = await connection.query(
            `SELECT saldo, tabungan, tabungan_status, tabungan_nama FROM users WHERE id = ? FOR UPDATE`,
            [userId]
        );

        if (rows.length === 0) throw new Error('User tidak ditemukan');

        const u = rows[0];

        if (u.tabungan_status !== 'active') {
            await connection.rollback();
            return res.status(400).json({ success: false, message: 'Tidak ada tabungan aktif untuk dibatalkan' });
        }

        const tabungan = parseFloat(u.tabungan);
        const saldoAfter = parseFloat(u.saldo) + tabungan;

        await connection.query(
            `UPDATE users SET
                saldo = ?, tabungan = 0, tabungan_status = 'none',
                tabungan_nama = NULL, tabungan_target = NULL, tabungan_total_cicilan = NULL,
                tabungan_cicilan_sudah = 0, tabungan_per_periode = NULL,
                tabungan_frekuensi = NULL, tabungan_next_due_at = NULL
             WHERE id = ?`,
            [saldoAfter, userId]
        );

        await connection.query(
            'INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)',
            [userId, 'Tabungan Dibatalkan', `Tabungan "${u.tabungan_nama}" dibatalkan. Rp ${tabungan.toLocaleString('id-ID')} dikembalikan ke saldo utama`, 'system']
        );

        await connection.commit();
        res.status(200).json({
            success: true,
            message: 'Tabungan berhasil dibatalkan dan saldo dikembalikan',
            saldoAfter,
            tabunganDikembalikan: tabungan
        });

    } catch (error) {
        await connection.rollback();
        console.error('Error batalkan tabungan:', error.message);
        res.status(500).json({ success: false, message: 'Gagal membatalkan tabungan' });
    } finally {
        connection.release();
    }
});

// ==========================================
// NOTIFIKASI
// Menampilkan SEMUA notifikasi user:
// topup, transfer_in, transfer_out, system
// (promo, tabungan, dan notifikasi sistem lainnya)
// ==========================================
router.get('/notifications', verifyTokenAndStatus, async (req, res) => {
    try {
        const userId = req.user.id;

        const [notifications] = await pool.query(`
            SELECT id, title, message, type, reference_id, is_read, created_at
            FROM notifications
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 50
        `, [userId]);

        const result = await Promise.all(notifications.map(async (notif) => {
            let amount = null;
            let detail = {};

            if (notif.type === 'topup' && notif.reference_id) {
                const [rows] = await pool.query(`
                    SELECT t.amount, t.saldo_before, t.saldo_after, t.note, t.status,
                           t.created_at AS trx_date, m.name AS merchant_name
                    FROM topup_transactions t
                    LEFT JOIN merchants m ON m.id = t.merchant_id
                    WHERE t.id = ? LIMIT 1
                `, [notif.reference_id]);
                if (rows[0]) {
                    amount = rows[0].amount;
                    detail = {
                        merchantName: rows[0].merchant_name || 'Merchant',
                        saldoBefore: rows[0].saldo_before,
                        saldoAfter: rows[0].saldo_after,
                        note: rows[0].note,
                        status: rows[0].status,
                        trxDate: rows[0].trx_date,
                    };
                }
            }

            if (notif.type === 'transfer_out' && notif.reference_id) {
                const [rows] = await pool.query(`
                    SELECT t.amount, t.note, t.status, t.created_at AS trx_date,
                           t.saldo_before_sender AS saldo_before, t.saldo_after_sender AS saldo_after,
                           r.name AS receiver_name, r.phone AS receiver_phone,
                           s.name AS sender_name, s.phone AS sender_phone
                    FROM transfer_transactions t
                    LEFT JOIN users r ON r.id = t.receiver_id
                    LEFT JOIN users s ON s.id = t.sender_id
                    WHERE t.id = ? LIMIT 1
                `, [notif.reference_id]);
                if (rows[0]) {
                    amount = rows[0].amount;
                    detail = {
                        senderName: rows[0].sender_name,
                        senderPhone: rows[0].sender_phone,
                        receiverName: rows[0].receiver_name,
                        receiverPhone: rows[0].receiver_phone,
                        saldoBefore: rows[0].saldo_before,
                        saldoAfter: rows[0].saldo_after,
                        note: rows[0].note,
                        status: rows[0].status,
                        trxDate: rows[0].trx_date,
                    };
                }
            }

            if (notif.type === 'transfer_in' && notif.reference_id) {
                const [rows] = await pool.query(`
                    SELECT t.amount, t.note, t.status, t.created_at AS trx_date,
                           t.saldo_before_receiver AS saldo_before, t.saldo_after_receiver AS saldo_after,
                           s.name AS sender_name, s.phone AS sender_phone,
                           r.name AS receiver_name, r.phone AS receiver_phone
                    FROM transfer_transactions t
                    LEFT JOIN users s ON s.id = t.sender_id
                    LEFT JOIN users r ON r.id = t.receiver_id
                    WHERE t.id = ? LIMIT 1
                `, [notif.reference_id]);
                if (rows[0]) {
                    amount = rows[0].amount;
                    detail = {
                        senderName: rows[0].sender_name,
                        senderPhone: rows[0].sender_phone,
                        receiverName: rows[0].receiver_name,
                        receiverPhone: rows[0].receiver_phone,
                        saldoBefore: rows[0].saldo_before,
                        saldoAfter: rows[0].saldo_after,
                        note: rows[0].note,
                        status: rows[0].status,
                        trxDate: rows[0].trx_date,
                    };
                }
            }

            // Fallback parse nominal dari message jika reference_id NULL (data lama)
            if (!amount) {
                const match = notif.message.match(/Rp[\s.]?([\d.]+)/);
                if (match) amount = parseFloat(match[1].replace(/\./g, ''));
            }

            return { ...notif, amount, detail };
        }));

        res.status(200).json({ success: true, data: result });
    } catch (error) {
        console.error("ERROR /notifications:", error.message);
        res.status(500).json({ success: false, message: "Gagal memuat notifikasi", debug: error.message });
    }
});

router.get('/notifications-stream', verifyTokenAndStatus, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    const userId = req.user.id;
    notificationClients.set(userId, res);

    req.on('close', () => {
        notificationClients.delete(userId);
    });
});

const emitNotification = (userId, data) => {
    const client = notificationClients.get(userId);
    if (client) {
        client.write(`data: ${JSON.stringify(data)}\n\n`);
    }
};

// ==========================================
// UBAH PIN
// ==========================================
router.put('/change-pin', verifyTokenAndStatus, async (req, res) => {
    try {
        const userId = req.user.id;
        const { pinLama, pinBaru } = req.body;

        if (!pinLama || !pinBaru) {
            return res.status(400).json({ success: false, message: "PIN lama dan PIN baru wajib diisi." });
        }

        if (!/^\d{6}$/.test(pinBaru)) {
            return res.status(400).json({ success: false, message: "PIN baru harus berupa 6 digit angka." });
        }

        // Ambil data PIN lama dari database
        const [rows] = await pool.query('SELECT password FROM users WHERE id = ?', [userId]);
        if (rows.length === 0) return res.status(404).json({ success: false, message: "User tidak ditemukan." });

        const user = rows[0];

        // Cocokkan PIN lama
        const match = await bcrypt.compare(pinLama, user.password);
        if (!match) {
            return res.status(401).json({ success: false, message: "PIN lama yang Anda masukkan salah." });
        }

        // Hash PIN baru dan simpan
        const saltRounds = 10;
        const hashedPin = await bcrypt.hash(pinBaru, saltRounds);

        await pool.query(
            'UPDATE users SET password = ?, pin = ? WHERE id = ?',
            [hashedPin, hashedPin, userId]
        );

        res.status(200).json({ success: true, message: "PIN berhasil diubah. Jaga kerahasiaan PIN Anda." });

    } catch (error) {
        console.error("Error Change PIN:", error.message);
        res.status(500).json({ success: false, message: "Kesalahan internal saat mengubah PIN." });
    }
});

// ==========================================
// KONTROL PERANGKAT TERHUBUNG
// ==========================================

// 1. Ambil semua perangkat yang sedang terhubung
router.get('/perangkat', verifyTokenAndStatus, async (req, res) => {
    try {
        const userId = req.user.id;
        const currentToken = req.headers['authorization']?.split(' ')[1] || req.query.token;

        const [rows] = await pool.query(
            'SELECT id, device_name, ip_address, updated_at, token FROM user_sessions WHERE user_id = ? ORDER BY updated_at DESC',
            [userId]
        );

        // Petakan data untuk menandai mana perangkat yang sedang dipegang user saat ini
        const perangkatList = rows.map(session => ({
            id: session.id,
            device_name: session.device_name,
            ip_address: session.ip_address,
            Terakhir_aktif: session.updated_at,
            is_current: session.token === currentToken
        }));

        res.status(200).json({ success: true, data: perangkatList });
    } catch (error) {
        console.error("Error GET /perangkat:", error.message);
        res.status(500).json({ success: false, message: "Gagal memuat daftar perangkat." });
    }
});

// 2. Hapus sesi perangkat tertentu (Log out perangkat lain)
router.delete('/perangkat/:id', verifyTokenAndStatus, async (req, res) => {
    try {
        const userId = req.user.id;
        const sessionId = req.params.id;

        // Pastikan sesi yang dihapus benar-benar milik user yang merequest
        const [result] = await pool.query(
            'DELETE FROM user_sessions WHERE id = ? AND user_id = ?',
            [sessionId, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "Sesi perangkat tidak ditemukan." });
        }

        res.status(200).json({ success: true, message: "Perangkat berhasil diputuskan." });
    } catch (error) {
        console.error("Error DELETE /perangkat:", error.message);
        res.status(500).json({ success: false, message: "Gagal memutuskan perangkat." });
    }
});

module.exports = router;