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
const { startRetentionScheduler } = require('./utils/retention');
const logger = require('./utils/logger');

const app = express();

// Trust proxy - important for getting real client IP when behind a reverse proxy
app.set('trust proxy', 1);

// ==================== BEZPEČNOST ====================
app.use(helmet());
const ALLOWED_ORIGINS = (process.env.FRONTEND_URL || 'http://localhost:3000')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
app.use(cors({
  origin: function (origin, callback) {
    // Povol requesty bez origin (curl, healthchecky, server-to-server)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS: origin ${origin} není povolen`));
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

// Ještě přísnější limit na zapomenuté heslo (zabraňuje spamu resetovacích mailů)
const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { error: 'Příliš mnoho žádostí o obnovu hesla. Zkuste to za 15 minut.' },
});
app.use('/api/auth/forgot-password', passwordResetLimiter);
app.use('/api/auth/reset-password', passwordResetLimiter);
app.use('/api/auth/resend-verification', passwordResetLimiter);

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
  logger.error({ err, path: req.path, method: req.method }, 'Unhandled error');
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'Soubor je příliš velký.' });
  }
  res.status(500).json({ error: 'Interní chyba serveru.' });
});

// ==================== START ====================
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';
app.listen(PORT, HOST, () => {
  logger.info(`Server běží na ${HOST}:${PORT}`);
  logger.info(`API: http://localhost:${PORT}/api`);
  startRetentionScheduler();

  // One-shot backfill: starší notifikace měly link `/projects/...` (anglicky),
  // ale FE route je `/projekty/...`. Přepíšeme je at fungují.
  const prisma = require('./prisma');
  prisma.$executeRaw`UPDATE "Notification" SET "link" = REPLACE("link", '/projects/', '/projekty/') WHERE "link" LIKE '/projects/%'`
    .then((count) => { if (count > 0) logger.info(`[backfill] Opraveno ${count} notifikací s /projects/ linkem.`); })
    .catch((err) => logger.warn({ err }, '[backfill] Notification link fix selhal'));
});