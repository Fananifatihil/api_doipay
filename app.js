require('dotenv').config();
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const methodOverride = require('method-override');
const path = require('path');
const cors = require('cors'); 

const app = express();
const PORT = process.env.PORT || 3000;

app.get("/status", (req, res) => {
    res.send('{"kode":"01", "status":"API Berbasis ExpressJS OK"}');
});

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());

// Method override
app.use(methodOverride('_method'));

// Session
app.use(session({
  secret: process.env.SESSION_SECRET || 'dogipay_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8 } // 8 jam
}));

// Flash messages
app.use(flash());

// Global variables untuk semua view
app.use((req, res, next) => {
  res.locals.appName = process.env.APP_NAME || 'DogiPay';
  res.locals.merchant = req.session.merchant || null;
  next();
});

// ==========================================
// ROUTES API MOBILE (DOGIPAY APP)
// ==========================================
// Semua endpoint untuk aplikasi HP akan otomatis diawali dengan /api
app.use('/api', require('./routes/api'));

// ==========================================
// ROUTES WEB DASHBOARD
// ==========================================
app.use('/', require('./routes/auth'));
app.use('/', require('./routes/dashboard'));
app.use('/', require('./routes/topup'));
app.use('/', require('./routes/customer'));
app.use('/', require('./routes/riwayat'));
app.use('/', require('./routes/estatement'));

// Redirect root ke dashboard
app.get('/', (req, res) => {
  res.redirect('/dashboard');
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('404', { title: '404 - DogiPay' });
});

app.listen(PORT, () => {
  console.log(`🚀 DogiPay running at http://localhost:${PORT}`);
});