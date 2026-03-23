const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const interviewRoutes = require('./routes/interviews');
const projectRoutes = require('./routes/projects');
const reviewRoutes = require('./routes/reviews');
const voteRoutes = require('./routes/votes');
const commentRoutes = require('./routes/comments');
const adminRoutes = require('./routes/admin');
const cmsRoutes = require('./routes/cms');

const app = express();

// Trust proxy - important for getting real client IP when behind a reverse proxy
app.set('trust proxy', 1);

// ==================== BEZPEČNOST ====================
app.use(helmet());
app.use(cors({
  origin: function (origin, callback) {
    const allowed = (process.env.FRONTEND_URL || 'http://localhost:3000').split(',').map(s => s.trim());
    // Allow requests with no origin (desktop apps, curl, etc.)
    if (!origin || allowed.includes(origin)) {
      callback(null, true);
    } else {
      callback(null, true); // MVP: allow all origins for now
    }
  },
  credentials: true,
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minut
  max: 100,
  message: { error: 'Příliš mnoho požadavků. Zkuste to později.' },
});
app.use('/api/', limiter);

// Přísnější rate limit pro auth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Příliš mnoho pokusů o přihlášení. Zkuste to za 15 minut.' },
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// ==================== MIDDLEWARE ====================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Statické soubory (přílohy)
app.use('/uploads', express.static(path.join(__dirname, '..', 'uploads')));

// ==================== ROUTES ====================
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/interviews', interviewRoutes);
app.use('/api/projects', projectRoutes);
app.use('/api/reviews', reviewRoutes);
app.use('/api/votes', voteRoutes);
app.use('/api/comments', commentRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/cms', cmsRoutes);

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'Soubor je příliš velký.' });
  }
  res.status(500).json({ error: 'Interní chyba serveru.' });
});

// ==================== START ====================
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';
app.listen(PORT, HOST, () => {
  console.log(`Server běží na ${HOST}:${PORT}`);
  console.log(`API: http://localhost:${PORT}/api`);
});