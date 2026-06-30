// Middleware: cek apakah merchant sudah login
const isAuthenticated = (req, res, next) => {
  if (req.session && req.session.merchant) {
    return next();
  }
  req.flash('error', 'Silakan login terlebih dahulu');
  return res.redirect('/login');
};

// Middleware: redirect ke dashboard jika sudah login
const isGuest = (req, res, next) => {
  if (req.session && req.session.merchant) {
    return res.redirect('/dashboard');
  }
  return next();
};

module.exports = { isAuthenticated, isGuest };
