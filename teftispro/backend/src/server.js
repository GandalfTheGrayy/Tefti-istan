// TeftişPro - Backend Server
// Teftiş ve Kalite Kontrol Uygulaması API

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const expressWinston = require('express-winston');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sharp = require('sharp');
const { PrismaClient } = require('@prisma/client');
const { z } = require('zod');
const { validate } = require('./middleware/validate');
const { passwordSchema } = require('./schemas/common');
const { updateCompanySchema, deleteCompanySchema } = require('./schemas/company.schema');
const { updateBranchSchema, assignBranchSchema } = require('./schemas/branch.schema');
const { profileUpdateSchema, profileSignatureSchema } = require('./schemas/profile.schema');
const { correctiveActionCreateSchema, correctiveActionUpdateSchema, auditCorrectiveActionsSchema } = require('./schemas/correctiveAction.schema');
const { auditParamsSchema, auditAnswersSchema, auditReviewSchema } = require('./schemas/audit.schema');
const { paramsIdSchema, paramsOnlySchema } = require('./schemas/common');
const PDFDocument = require('pdfkit');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const logger = require('./logger');
const audit = require('./audit');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET ortam değişkeni tanımlı değil. Uygulama başlatılamıyor.');
  process.exit(1);
}

const prisma = new PrismaClient();

// Faz 4.3: Prisma middleware - User modelinden password alanını API yanıtlarından çıkar
// Login için prismaWithPassword kullanılır (bcrypt.compare için password gerekli)
const prismaWithPassword = new PrismaClient();
prisma.$use(async (params, next) => {
  const result = await next(params);
  if (params.model === 'User' && result) {
    const items = Array.isArray(result) ? result : [result];
    items.forEach(u => { if (u && typeof u === 'object') delete u.password; });
  }
  return result;
});

audit.init(prismaWithPassword);
const { createAuditLog, maskEmail } = audit;

const app = express();
const PORT = process.env.PORT || 3636;

// Faz 4.4: Express sunucu imzasını gizle
app.disable('x-powered-by');

// Uploads klasörü
const uploadsDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Dosya güvenliği - 1.5, 1.5c
const ALLOWED_IMAGE_MIME = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const ALLOWED_IMAGE_EXT = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
const ALLOWED_WITH_PDF_MIME = [...ALLOWED_IMAGE_MIME, 'application/pdf'];
const ALLOWED_WITH_PDF_EXT = [...ALLOWED_IMAGE_EXT, '.pdf'];

function checkMagicBytes(filePath, mimeType) {
  const buf = Buffer.alloc(12);
  const fd = fs.openSync(filePath, 'r');
  fs.readSync(fd, buf, 0, 12, 0);
  fs.closeSync(fd);
  if (mimeType === 'image/jpeg' || mimeType === 'image/jpg') {
    return buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
  }
  if (mimeType === 'image/png') {
    return buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47;
  }
  if (mimeType === 'image/gif') {
    return buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46;
  }
  if (mimeType === 'image/webp') {
    return buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46;
  }
  if (mimeType === 'application/pdf') {
    return buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46;
  }
  return false;
}

async function compressImage(inputPath, options = {}) {
  const { maxWidth = 1920, quality = 80, format = 'jpeg' } = options;
  const metadata = await sharp(inputPath).metadata();
  const needResize = metadata.width > maxWidth;
  let pipeline = sharp(inputPath);
  if (needResize) {
    pipeline = pipeline.resize(maxWidth, null, { withoutEnlargement: true });
  }
  const basePath = inputPath.replace(/\.[^.]+$/, '');
  const outputPath = `${basePath}.${format === 'jpeg' ? 'jpg' : 'png'}`;
  const tempPath = `${basePath}.tmp${Date.now()}`;
  try {
    if (format === 'jpeg') {
      await pipeline.jpeg({ quality }).toFile(tempPath);
    } else if (format === 'png') {
      await pipeline.png({ compressionLevel: 9 }).toFile(tempPath);
    } else {
      return inputPath;
    }
    fs.unlinkSync(inputPath);
    fs.renameSync(tempPath, outputPath);
    return outputPath;
  } catch (error) {
    try { fs.unlinkSync(tempPath); } catch (_) {}
    throw error;
  }
}

function createFileFilter(allowedMime, allowedExt) {
  return (req, file, cb) => {
    if (file.originalname.includes('..') || file.originalname.includes('\0')) {
      return cb(new Error('Geçersiz dosya adı'), false);
    }
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedMime.includes(file.mimetype) && allowedExt.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Desteklenmeyen dosya formatı. İzin verilen: JPG, PNG, GIF, WebP' + (allowedExt.includes('.pdf') ? ', PDF' : '')), false);
    }
  };
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname).toLowerCase();
    const safeExt = ALLOWED_IMAGE_EXT.includes(ext) ? ext : (ALLOWED_WITH_PDF_EXT.includes(ext) ? ext : '.jpg');
    cb(null, uniqueSuffix + safeExt);
  }
});

const uploadImagesOnly = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: createFileFilter(ALLOWED_IMAGE_MIME, ALLOWED_IMAGE_EXT)
});

const uploadWithPdf = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: createFileFilter(ALLOWED_WITH_PDF_MIME, ALLOWED_WITH_PDF_EXT)
});

// CORS - 1.2
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean);

// Helmet + CSP - 1.6
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://cdn.sheetjs.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  crossOriginEmbedderPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// HTTPS yönlendirmesi - 1.7
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, `https://${req.hostname}${req.url}`);
    }
    next();
  });
}

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS politikası tarafından engellendi'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  maxAge: 600
}));
app.use(cookieParser());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Faz 5: Yapılandırılmış HTTP loglama (Morgan yerine)
app.use(expressWinston.logger({
  winstonInstance: logger,
  meta: true,
  msg: 'HTTP {{req.method}} {{req.url}} {{res.statusCode}} {{res.responseTime}}ms',
  expressFormat: false,
  colorize: false,
  dynamicMeta: (req, res) => ({
    userId: req.user?.id ?? null,
    userEmail: req.user?.email ?? null,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  })
}));

// Faz 5: Rate limit aşıldığında denetim izi
function rateLimitHandler(message, resourceLabel) {
  return async (req, res) => {
    createAuditLog({
      userId: req.user?.id ?? null,
      userEmail: req.user?.email ?? null,
      action: 'RATE_LIMIT',
      resource: resourceLabel,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: req.path || req.url
    });
    res.status(429).json(message);
  };
}

// Rate Limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: 200,
  message: { error: 'Çok fazla istek. Lütfen daha sonra tekrar deneyin.' },
  handler: rateLimitHandler({ error: 'Çok fazla istek. Lütfen daha sonra tekrar deneyin.' }, 'API')
});

// Faz 2.6: Login rate limit sıkılaştırma
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX || '5', 10),
  message: { error: 'Çok fazla giriş denemesi. 15 dakika sonra tekrar deneyin.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.body?.email || req.ip,
  handler: rateLimitHandler({ error: 'Çok fazla giriş denemesi. 15 dakika sonra tekrar deneyin.' }, 'Auth')
});

// Faz 4.5: Endpoint bazlı rate limit'ler
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Çok fazla dosya yükleme denemesi.' },
  handler: rateLimitHandler({ error: 'Çok fazla dosya yükleme denemesi.' }, 'Upload')
});

const writeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Çok fazla yazma işlemi.' },
  handler: rateLimitHandler({ error: 'Çok fazla yazma işlemi.' }, 'Write')
});

// Faz 4.4: Async handler - hataları global error handler'a iletir (Prisma P2002, P2025 vb.)
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.use(generalLimiter);

// CSRF token store - user-bound tokens for mobile, loginOnly for web/mobile login
const csrfTokenStore = new Map(); // token -> { issuedAt, userId?, loginOnly? }
const CSRF_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

function cleanupExpiredCsrfTokens() {
  const now = Date.now();
  for (const [token, data] of csrfTokenStore.entries()) {
    if (now - data.issuedAt > CSRF_TOKEN_TTL_MS) {
      csrfTokenStore.delete(token);
    }
  }
}
setInterval(cleanupExpiredCsrfTokens, 15 * 60 * 1000); // every 15 min

// Faz 3.3: CSRF token doğrulama middleware
function validateCSRF(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  // Only /auth/refresh exempt - token renewal when access token expired
  if (req.path === '/auth/refresh') {
    return next();
  }
  const cookieToken = req.cookies?.csrf_token;
  const headerToken = req.headers['x-csrf-token'];

  // Web: cookie + header must match
  if (cookieToken && headerToken && cookieToken === headerToken) {
    return next();
  }

  // Mobile or cookie mismatch: validate header token from store (header takes precedence when Bearer present)
  if (headerToken) {
    const stored = csrfTokenStore.get(headerToken);
    if (!stored) {
      createAuditLog({
        action: 'CSRF_FAILED',
        resource: 'Auth',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: 'Token depoda bulunamadı'
      });
      return res.status(403).json({ error: 'Geçersiz CSRF token' });
    }
    if (stored.issuedAt && (Date.now() - stored.issuedAt) > CSRF_TOKEN_TTL_MS) {
      csrfTokenStore.delete(headerToken);
      createAuditLog({
        action: 'CSRF_FAILED',
        resource: 'Auth',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: 'Token süresi doldu'
      });
      return res.status(403).json({ error: 'Geçersiz CSRF token' });
    }
    if (stored.loginOnly) {
      if (req.path === '/auth/login') {
        return next();
      }
      createAuditLog({
        action: 'CSRF_FAILED',
        resource: 'Auth',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: 'LoginOnly token yanlış path için kullanıldı'
      });
      return res.status(403).json({ error: 'Geçersiz CSRF token' });
    }
    if (stored.userId != null) {
      const bearerToken = req.headers.authorization?.startsWith('Bearer ')
        ? req.headers.authorization.split(' ')[1]
        : null;
      if (!bearerToken) {
        createAuditLog({
          action: 'CSRF_FAILED',
          resource: 'Auth',
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          details: 'Bearer token eksik'
        });
        return res.status(403).json({ error: 'Geçersiz CSRF token' });
      }
      try {
        const decoded = jwt.verify(bearerToken, JWT_SECRET);
        if (decoded.id !== stored.userId) {
          createAuditLog({
            action: 'CSRF_FAILED',
            resource: 'Auth',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            details: 'Token userId eşleşmedi'
          });
          return res.status(403).json({ error: 'Geçersiz CSRF token' });
        }
        return next();
      } catch (err) {
        createAuditLog({
          action: 'CSRF_FAILED',
          resource: 'Auth',
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          details: 'Bearer token geçersiz'
        });
        return res.status(403).json({ error: 'Geçersiz CSRF token' });
      }
    }
  }

  createAuditLog({
    action: 'CSRF_FAILED',
    resource: 'Auth',
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    details: headerToken ? 'Token uyuşmazlığı' : 'Token eksik'
  });
  return res.status(403).json({ error: 'Geçersiz CSRF token' });
}
app.use(validateCSRF);

// ============ HELPER FUNCTIONS ============

// Faz 2.2: Şifre karmaşıklık politikası (common.js'den import edildi)
const BCRYPT_ROUNDS = 12;

// JWT Token oluşturma - Faz 2.4
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role.name, type: 'access' },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    { id: user.id, type: 'refresh' },
    JWT_SECRET,
    { expiresIn: JWT_REFRESH_EXPIRES_IN }
  );
}

const cookieOptions = (maxAge) => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge,
  path: '/'
});

const refreshCookieOptions = (maxAge) => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge,
  path: '/auth/refresh'
});

// JWT Token doğrulama middleware - Faz 2.1: Cookie + header fallback
async function authenticate(req, res, next) {
  const auditCtx = { ipAddress: req.ip, userAgent: req.get('User-Agent'), resource: 'Auth' };
  try {
    const token = req.cookies?.access_token ||
      (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.split(' ')[1] : null);

    if (!token) {
      createAuditLog({ ...auditCtx, action: 'ACCESS_DENIED', details: 'Token eksik' });
      return res.status(401).json({ error: 'Kimlik doğrulama gerekli' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await prismaWithPassword.user.findUnique({
      where: { id: decoded.id },
      include: { role: true }
    });

    if (!user) {
      createAuditLog({ ...auditCtx, action: 'ACCESS_DENIED', details: 'Kullanıcı bulunamadı' });
      return res.status(401).json({ error: 'Kullanıcı bulunamadı' });
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      createAuditLog({ ...auditCtx, action: 'ACCESS_DENIED', details: 'Token süresi doldu' });
      return res.status(401).json({ error: 'Oturum süresi doldu', code: 'TOKEN_EXPIRED' });
    }
    createAuditLog({ ...auditCtx, action: 'ACCESS_DENIED', details: 'Geçersiz token' });
    return res.status(401).json({ error: 'Geçersiz token' });
  }
}

// Rol kontrolü middleware
function authorize(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role.name)) {
      createAuditLog({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'ACCESS_DENIED',
        resource: req.path || 'API',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: 'Yetkisiz erişim'
      });
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }
    next();
  };
}

// Puan hesaplama fonksiyonu
const SCORE_MAP = { U: 1, YP: 0.5, UD: 0, DD: 0 };

function calculateScore(answers, questions) {
  const questionMap = new Map(questions.map(q => [q.id, q]));

  const effectiveAnswers = answers.filter(a => a.value !== 'DD');

  const totalPoints = effectiveAnswers.reduce((sum, a) => {
    const question = questionMap.get(a.questionId);
    return sum + (question?.points || 0);
  }, 0);

  const earnedPoints = effectiveAnswers.reduce((sum, a) => {
    const question = questionMap.get(a.questionId);
    const multiplier = SCORE_MAP[a.value] ?? 0;
    return sum + ((question?.points || 0) * multiplier);
  }, 0);

  const percent = totalPoints ? Math.round((earnedPoints / totalPoints) * 100) : 0;

  // Kategori bazlı döküm
  const categoryScores = {};
  for (const answer of effectiveAnswers) {
    const question = questionMap.get(answer.questionId);
    if (!question) continue;

    const catId = question.categoryId;
    if (!categoryScores[catId]) {
      categoryScores[catId] = { categoryId: catId, title: question.category?.title || '', totalPoints: 0, earnedPoints: 0 };
    }

    categoryScores[catId].totalPoints += question.points || 0;
    categoryScores[catId].earnedPoints += (question.points || 0) * (SCORE_MAP[answer.value] ?? 0);
  }

  const byCategory = Object.values(categoryScores).map(cat => ({
    ...cat,
    percent: cat.totalPoints ? Math.round((cat.earnedPoints / cat.totalPoints) * 100) : 0
  }));

  return { totalPoints, earnedPoints, percent, byCategory };
}

// ============ AUTH ENDPOINTS ============

// GET /auth/csrf-token - Faz 3.3: CSRF token (web: loginOnly, mobile: userId-bound)
app.get('/auth/csrf-token', (req, res, next) => {
  const hasBearer = req.headers.authorization?.startsWith('Bearer ');
  if (hasBearer) {
    return authenticate(req, res, (err) => {
      if (err) return next(err);
      const csrfToken = crypto.randomBytes(32).toString('hex');
      csrfTokenStore.set(csrfToken, { issuedAt: Date.now(), userId: req.user.id });
      res.json({ csrfToken });
    });
  }
  const csrfToken = crypto.randomBytes(32).toString('hex');
  csrfTokenStore.set(csrfToken, { issuedAt: Date.now(), loginOnly: true });
  res.cookie('csrf_token', csrfToken, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 1000,
    path: '/'
  });
  res.json({ csrfToken });
});

// POST /auth/login - Kullanıcı girişi (Faz 2.1 cookie, 2.3 hesap kilitleme)
app.post('/auth/login', loginLimiter, async (req, res) => {
  try {
    const schema = z.object({
      email: z.string().email('Geçerli bir e-posta adresi girin'),
      password: z.string().min(1, 'Şifre gerekli')
    });

    const { email, password } = schema.parse(req.body);

    const user = await prismaWithPassword.user.findUnique({
      where: { email },
      include: { role: true }
    });

    if (!user) {
      await createAuditLog({
        action: 'LOGIN_FAILED',
        resource: 'User',
        details: maskEmail(email) || 'Bilinmeyen e-posta',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });
      return res.status(401).json({ error: 'E-posta veya şifre hatalı' });
    }

    // Faz 2.3: Hesap kilitleme kontrolü
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      await createAuditLog({
        action: 'LOGIN_FAILED',
        resource: 'User',
        resourceId: user.id,
        details: 'Hesap kilitli',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });
      const remainingMinutes = Math.ceil((user.lockedUntil - new Date()) / 60000);
      return res.status(423).json({
        error: `Hesap kilitli. ${remainingMinutes} dakika sonra tekrar deneyin.`
      });
    }

    const isValid = await bcrypt.compare(password, user.password);

    if (!isValid) {
      await createAuditLog({
        action: 'LOGIN_FAILED',
        resource: 'User',
        resourceId: user.id,
        details: maskEmail(email),
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });
      const attempts = (user.failedLoginAttempts || 0) + 1;
      const updateData = { failedLoginAttempts: attempts };

      if (attempts >= 5) {
        updateData.lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 dk
        updateData.failedLoginAttempts = 0;
      }

      await prismaWithPassword.user.update({ where: { id: user.id }, data: updateData });
      return res.status(401).json({ error: 'E-posta veya şifre hatalı' });
    }

    // Başarılı giriş — sayacı sıfırla
    await prismaWithPassword.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0, lockedUntil: null }
    });

    const token = generateToken(user);
    const refreshToken = generateRefreshToken(user);

    // Faz 2.1: HttpOnly cookie olarak set et
    res.cookie('access_token', token, cookieOptions(60 * 60 * 1000)); // 1 saat
    res.cookie('refresh_token', refreshToken, refreshCookieOptions(7 * 24 * 60 * 60 * 1000)); // 7 gün

    await createAuditLog({
      userId: user.id,
      userEmail: user.email,
      action: 'LOGIN',
      resource: 'User',
      resourceId: String(user.id),
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role.name,
        profilePhoto: user.profilePhoto,
        signatureUrl: user.signatureUrl,
        companyId: user.companyId,
        branchId: user.branchId
      },
      accessToken: token,
      refreshToken,
      token
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /auth/refresh - Faz 2.4: Token yenileme (cookie veya Bearer header - mobil için)
app.post('/auth/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies?.refresh_token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token bulunamadı' });
    }

    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    if (decoded.type !== 'refresh') {
      return res.status(401).json({ error: 'Geçersiz token tipi' });
    }

    const user = await prismaWithPassword.user.findUnique({
      where: { id: decoded.id },
      include: { role: true }
    });

    if (!user) {
      return res.status(401).json({ error: 'Kullanıcı bulunamadı' });
    }

    const newAccessToken = generateToken(user);

    res.cookie('access_token', newAccessToken, cookieOptions(60 * 60 * 1000));

    createAuditLog({
      userId: user.id,
      userEmail: user.email,
      action: 'LOGIN',
      resource: 'User',
      resourceId: String(user.id),
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: 'Token yenilendi'
    });

    res.json({ message: 'Token yenilendi', accessToken: newAccessToken, token: newAccessToken });
  } catch (error) {
    res.clearCookie('access_token', { path: '/' });
    res.clearCookie('refresh_token', { path: '/auth/refresh' });
    return res.status(401).json({ error: 'Oturum süresi doldu, tekrar giriş yapın' });
  }
});

// POST /auth/logout - Faz 2.5: Çıkış yapma
app.post('/auth/logout', (req, res) => {
  // Logout: req.user yok (authenticate yok). Cookie'den token var ama decode etmeden user bilmiyoruz.
  // Basit LOGOUT: ipAddress ile logla
  createAuditLog({
    action: 'LOGOUT',
    resource: 'User',
    ipAddress: req.ip,
    userAgent: req.get('User-Agent')
  });
  res.clearCookie('access_token', { path: '/' });
  res.clearCookie('refresh_token', { path: '/auth/refresh' });
  res.json({ message: 'Çıkış yapıldı' });
});

// GET /auth/me - Mevcut kullanıcı bilgisi
app.get('/auth/me', authenticate, async (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    role: req.user.role.name,
    profilePhoto: req.user.profilePhoto,
    signatureUrl: req.user.signatureUrl,
    companyId: req.user.companyId,
    branchId: req.user.branchId
  });
});

// Uploads - 1.8: Kimlik doğrulamalı erişim
app.use('/uploads', authenticate, express.static(uploadsDir));

// ============ USERS ENDPOINTS ============

// GET /users - Kullanıcı listesi
app.get('/users', authenticate, authorize('admin', 'planlamacı'), async (req, res) => {
  try {
    const { role } = req.query;

    const where = {};
    if (role) {
      where.role = { name: role };
    }

    const users = await prisma.user.findMany({
      where,
      include: { role: true },
      orderBy: { createdAt: 'desc' }
    });

    res.json(users.map(u => ({
      id: u.id,
      name: u.name,
      email: u.email,
      role: u.role.name,
      profilePhoto: u.profilePhoto,
      companyId: u.companyId,
      branchId: u.branchId,
      createdAt: u.createdAt
    })));
  } catch (error) {
    logger.error('Get users error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /users - Yeni kullanıcı oluşturma (Faz 2.2 şifre politikası)
app.post('/users', authenticate, authorize('admin'), writeLimiter, async (req, res) => {
  try {
    const schema = z.object({
      name: z.string().min(1, 'Ad Soyad gerekli'),
      email: z.string().email('Geçerli bir e-posta adresi girin'),
      password: passwordSchema,
      role: z.string(),
      companyId: z.number().optional(),
      branchId: z.number().optional()
    });

    const data = schema.parse(req.body);

    // Rol ID'sini bul
    const role = await prisma.role.findUnique({ where: { name: data.role } });
    if (!role) {
      return res.status(400).json({ error: 'Geçersiz rol' });
    }

    // E-posta kontrolü
    const existing = await prisma.user.findUnique({ where: { email: data.email } });
    if (existing) {
      return res.status(400).json({ error: 'Bu e-posta adresi zaten kullanılıyor' });
    }

    const hashedPassword = await bcrypt.hash(data.password, BCRYPT_ROUNDS);

    const user = await prisma.user.create({
      data: {
        name: data.name,
        email: data.email,
        password: hashedPassword,
        roleId: role.id,
        companyId: data.companyId,
        branchId: data.branchId
      },
      include: { role: true }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'CREATE',
      resource: 'User',
      resourceId: String(user.id),
      newValue: { id: user.id, email: user.email, role: user.role.name },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(201).json({
      id: user.id,
      email: user.email,
      role: user.role.name
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    logger.error('Create user error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /users/:id - Kullanıcı silme (Faz 4.1 validasyon)
app.delete('/users/:id', authenticate, authorize('admin'), validate(paramsOnlySchema), writeLimiter, async (req, res) => {
  try {
    const { id } = req.validated.params;

    const deletedUser = await prisma.user.findUnique({ where: { id }, include: { role: true } });
    await prisma.user.delete({ where: { id } });

    if (deletedUser) {
      createAuditLog({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'DELETE',
        resource: 'User',
        resourceId: String(id),
        oldValue: { id: deletedUser.id, email: deletedUser.email, role: deletedUser.role?.name },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });
    }

    res.json({ message: 'Kullanıcı silindi' });
  } catch (error) {
    logger.error('Delete user error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ COMPANIES ENDPOINTS ============

// GET /companies - Şirket listesi
app.get('/companies', authenticate, authorize('admin', 'planlamacı', 'firma_sahibi'), async (req, res) => {
  try {
    let where = {};

    // Firma sahibi sadece kendi şirketini görür (companyId veya owner olarak)
    if (req.user.role.name === 'firma_sahibi') {
      if (req.user.companyId) {
        where = { id: req.user.companyId };
      } else {
        where = { ownerId: req.user.id };
      }
    }

    const companies = await prisma.company.findMany({
      where,
      include: {
        regions: true,
        branches: true,
        owner: { select: { id: true, email: true } }
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(companies);
  } catch (error) {
    logger.error('Get companies error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /companies - Yeni şirket oluşturma
app.post('/companies', authenticate, authorize('admin'), writeLimiter, async (req, res) => {
  try {
    const schema = z.object({
      name: z.string().min(1, 'Şirket adı gerekli'),
      logoUrl: z.string().optional(),
      ownerId: z.number().optional()
    });

    const data = schema.parse(req.body);

    const company = await prisma.company.create({
      data,
      include: { owner: { select: { id: true, email: true } } }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'CREATE',
      resource: 'Company',
      resourceId: String(company.id),
      newValue: { id: company.id, name: company.name },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(201).json(company);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    logger.error('Create company error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// PUT /companies/:id - Şirket güncelleme (Faz 4.1 validasyon)
app.put('/companies/:id', authenticate, authorize('admin'), validate(updateCompanySchema), writeLimiter, async (req, res) => {
  try {
    const { id } = req.validated.params;
    const { name, logoUrl, ownerId } = req.validated.body;

    const oldCompany = await prisma.company.findUnique({ where: { id } });
    const company = await prisma.company.update({
      where: { id },
      data: { name, logoUrl, ownerId },
      include: { owner: { select: { id: true, email: true } } }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'UPDATE',
      resource: 'Company',
      resourceId: String(id),
      oldValue: oldCompany ? { name: oldCompany.name } : null,
      newValue: { name: company.name, logoUrl: company.logoUrl, ownerId: company.ownerId },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json(company);
  } catch (error) {
    logger.error('Update company error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /companies/:id - Şirket silme (Faz 4.1 validasyon)
app.delete('/companies/:id', authenticate, authorize('admin'), validate(deleteCompanySchema), writeLimiter, async (req, res) => {
  try {
    const { id } = req.validated.params;

    const oldCompany = await prisma.company.findUnique({ where: { id } });
    await prisma.company.delete({ where: { id } });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'DELETE',
      resource: 'Company',
      resourceId: String(id),
      oldValue: oldCompany ? { id: oldCompany.id, name: oldCompany.name } : null,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({ message: 'Şirket silindi' });
  } catch (error) {
    logger.error('Delete company error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ REGIONS ENDPOINTS ============

// GET /regions - Bölge listesi
app.get('/regions', authenticate, authorize('admin', 'planlamacı'), async (req, res) => {
  try {
    const { companyId } = req.query;

    const where = {};
    if (companyId) {
      where.companyId = parseInt(companyId);
    }

    const regions = await prisma.region.findMany({
      where,
      include: {
        company: true,
        branches: true
      },
      orderBy: { name: 'asc' }
    });

    res.json(regions);
  } catch (error) {
    logger.error('Get regions error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /regions - Yeni bölge oluşturma
app.post('/regions', authenticate, authorize('admin'), writeLimiter, async (req, res) => {
  try {
    const schema = z.object({
      name: z.string().min(1, 'Bölge adı gerekli'),
      companyId: z.number()
    });

    const data = schema.parse(req.body);

    const region = await prisma.region.create({
      data,
      include: { company: true }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'CREATE',
      resource: 'Region',
      resourceId: String(region.id),
      newValue: { id: region.id, name: region.name, companyId: region.companyId },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(201).json(region);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    logger.error('Create region error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /regions/:id - Bölge silme (Faz 4.1 validasyon)
app.delete('/regions/:id', authenticate, authorize('admin'), validate(paramsOnlySchema), writeLimiter, async (req, res) => {
  try {
    const { id } = req.validated.params;

    const oldRegion = await prisma.region.findUnique({ where: { id } });
    await prisma.region.delete({ where: { id } });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'DELETE',
      resource: 'Region',
      resourceId: String(id),
      oldValue: oldRegion ? { id: oldRegion.id, name: oldRegion.name } : null,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({ message: 'Bölge silindi' });
  } catch (error) {
    logger.error('Delete region error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ BRANCHES ENDPOINTS ============

// GET /branches - Şube listesi
app.get('/branches', authenticate, async (req, res) => {
  try {
    const { regionId, companyId } = req.query;

    let where = {};

    // Field kullanıcı sadece atandığı şubeleri görür
    if (req.user.role.name === 'field') {
      const assignments = await prisma.branchAssignment.findMany({
        where: { userId: req.user.id },
        select: { branchId: true }
      });
      where.id = { in: assignments.map(a => a.branchId) };
    }

    // Firma sahibi sadece kendi şirketinin şubelerini görür
    if (req.user.role.name === 'firma_sahibi' && req.user.companyId) {
      where.companyId = req.user.companyId;
    }

    // Şube kullanıcısı sadece kendi şubesini görür
    if (req.user.role.name === 'sube_kullanici' && req.user.branchId) {
      where.id = req.user.branchId;
    }

    if (regionId) {
      where.regionId = parseInt(regionId);
    }

    if (companyId) {
      where.companyId = parseInt(companyId);
    }

    const branches = await prisma.branch.findMany({
      where,
      include: {
        company: true,
        region: true,
        assignments: { include: { user: { select: { id: true, email: true } } } }
      },
      orderBy: { name: 'asc' }
    });

    res.json(branches);
  } catch (error) {
    logger.error('Get branches error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /branches - Yeni şube oluşturma
app.post('/branches', authenticate, authorize('admin'), writeLimiter, async (req, res) => {
  try {
    const schema = z.object({
      name: z.string().min(1, 'Şube adı gerekli'),
      city: z.string().min(1, 'Şehir gerekli'),
      address: z.string().optional(),
      phone: z.string().optional(),
      email: z.string().email().optional().or(z.literal('')),
      companyId: z.number(),
      regionId: z.number().optional()
    });

    const data = schema.parse(req.body);

    const branch = await prisma.branch.create({
      data: {
        ...data,
        email: data.email || null
      },
      include: { company: true, region: true }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'CREATE',
      resource: 'Branch',
      resourceId: String(branch.id),
      newValue: { id: branch.id, name: branch.name, city: branch.city },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(201).json(branch);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    logger.error('Create branch error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// PUT /branches/:id - Şube güncelleme (Faz 4.1 validasyon)
app.put('/branches/:id', authenticate, authorize('admin'), validate(updateBranchSchema), writeLimiter, async (req, res) => {
  try {
    const { id } = req.validated.params;
    const { name, city, address, phone, email, regionId, isActive } = req.validated.body;

    const oldBranch = await prisma.branch.findUnique({ where: { id } });
    const branch = await prisma.branch.update({
      where: { id },
      data: { name, city, address, phone, email: email || null, regionId, isActive },
      include: { company: true, region: true }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'UPDATE',
      resource: 'Branch',
      resourceId: String(id),
      oldValue: oldBranch ? { name: oldBranch.name, city: oldBranch.city } : null,
      newValue: { name: branch.name, city: branch.city },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json(branch);
  } catch (error) {
    logger.error('Update branch error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /branches/:id - Şube silme (Faz 4.1 validasyon)
app.delete('/branches/:id', authenticate, authorize('admin'), validate(paramsOnlySchema), writeLimiter, async (req, res) => {
  try {
    const { id } = req.validated.params;

    const oldBranch = await prisma.branch.findUnique({ where: { id } });
    await prisma.branch.delete({ where: { id } });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'DELETE',
      resource: 'Branch',
      resourceId: String(id),
      oldValue: oldBranch ? { id: oldBranch.id, name: oldBranch.name } : null,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({ message: 'Şube silindi' });
  } catch (error) {
    logger.error('Delete branch error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /branches/:id/assign - Denetçi atama (Faz 4.1 validasyon)
app.post('/branches/:id/assign', authenticate, authorize('admin', 'planlamacı'), validate(assignBranchSchema), writeLimiter, async (req, res) => {
  try {
    const { id: branchId } = req.validated.params;
    const { userId } = req.validated.body;

    const assignment = await prisma.branchAssignment.create({
      data: { branchId, userId },
      include: { branch: true, user: { select: { id: true, email: true } } }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'UPDATE',
      resource: 'Branch',
      resourceId: String(branchId),
      newValue: { branchId, userId },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: 'Şube ataması'
    });

    res.status(201).json(assignment);
  } catch (error) {
    logger.error('Assign branch error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ CATEGORIES ENDPOINTS ============

// GET /categories - Kategori listesi
app.get('/categories', authenticate, async (req, res) => {
  try {
    const categories = await prisma.category.findMany({
      include: {
        questions: {
          orderBy: { id: 'asc' }
        }
      },
      orderBy: { id: 'asc' }
    });

    res.json(categories);
  } catch (error) {
    logger.error('Get categories error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /categories - Yeni kategori oluşturma
app.post('/categories', authenticate, authorize('admin'), writeLimiter, async (req, res) => {
  try {
    const schema = z.object({
      title: z.string().min(1, 'Kategori başlığı gerekli')
    });

    const data = schema.parse(req.body);

    const category = await prisma.category.create({
      data,
      include: { questions: true }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'CREATE',
      resource: 'Category',
      resourceId: String(category.id),
      newValue: { id: category.id, title: category.title },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(201).json(category);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    logger.error('Create category error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /categories/:id - Kategori silme (Faz 4.1 validasyon)
app.delete('/categories/:id', authenticate, authorize('admin'), validate(paramsOnlySchema), writeLimiter, async (req, res) => {
  try {
    const { id } = req.validated.params;

    const oldCategory = await prisma.category.findUnique({ where: { id } });
    await prisma.category.delete({ where: { id } });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'DELETE',
      resource: 'Category',
      resourceId: String(id),
      oldValue: oldCategory ? { id: oldCategory.id, title: oldCategory.title } : null,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({ message: 'Kategori silindi' });
  } catch (error) {
    logger.error('Delete category error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ QUESTIONS ENDPOINTS ============

// POST /questions - Yeni soru oluşturma
app.post('/questions', authenticate, authorize('admin'), writeLimiter, async (req, res) => {
  try {
    const schema = z.object({
      text: z.string().min(1, 'Soru metni gerekli'),
      description: z.string().optional(),
      points: z.number().default(5),
      noteRequired: z.boolean().default(false),
      imageUrl: z.string().optional(),
      categoryId: z.number()
    });

    const data = schema.parse(req.body);

    const question = await prisma.question.create({
      data,
      include: { category: true }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'CREATE',
      resource: 'Question',
      resourceId: String(question.id),
      newValue: { id: question.id, text: question.text?.substring(0, 50) },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(201).json(question);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    logger.error('Create question error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /questions/:id - Soru silme (Faz 4.1 validasyon)
app.delete('/questions/:id', authenticate, authorize('admin'), validate(paramsOnlySchema), writeLimiter, async (req, res) => {
  try {
    const { id } = req.validated.params;

    const oldQuestion = await prisma.question.findUnique({ where: { id } });
    await prisma.question.delete({ where: { id } });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'DELETE',
      resource: 'Question',
      resourceId: String(id),
      oldValue: oldQuestion ? { id: oldQuestion.id } : null,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({ message: 'Soru silindi' });
  } catch (error) {
    logger.error('Delete question error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ AUDITS ENDPOINTS ============

// GET /audits - Denetim listesi
app.get('/audits', authenticate, async (req, res) => {
  try {
    const { status, startDate, endDate, companyId, userId, branchId, search } = req.query;

    let where = { deletedAt: null };

    // Rol bazlı kapsam: field, firma_sahibi, sube_kullanici sadece kendi verilerini görür
    if (req.user.role.name === 'field') {
      where.userId = req.user.id;
    }
    if (req.user.role.name === 'firma_sahibi' && req.user.companyId) {
      where.companyId = req.user.companyId;
    }
    if (req.user.role.name === 'sube_kullanici' && req.user.branchId) {
      where.branchId = req.user.branchId;
    }

    // companyId, userId, branchId sadece yetkili roller (admin, planlamacı, gözden_geçiren) için uygulanır
    const PRIVILEGED_AUDIT_ROLES = ['admin', 'planlamacı', 'gözden_geçiren'];
    const canFilterByScope = PRIVILEGED_AUDIT_ROLES.includes(req.user.role.name);

    if (companyId && canFilterByScope) {
      const cid = parseInt(companyId, 10);
      if (!isNaN(cid)) where.companyId = cid;
    }
    if (userId && canFilterByScope && typeof userId === 'string' && userId.trim()) {
      where.userId = userId.trim();
    }
    if (branchId && canFilterByScope) {
      const bid = parseInt(branchId, 10);
      if (!isNaN(bid)) where.branchId = bid;
    }

    if (status) {
      where.status = status;
    }

    if (search && typeof search === 'string' && search.trim()) {
      const s = search.trim();
      where.OR = [
        { title: { contains: s } },
        { id: { contains: s } },
        { user: { email: { contains: s } } },
        { branch: { name: { contains: s } } }
      ];
    }

    if (startDate || endDate) {
      where.createdAt = {};
      if (startDate) where.createdAt.gte = new Date(startDate);
      if (endDate) where.createdAt.lte = new Date(endDate + 'T23:59:59.999Z');
    }

    const audits = await prisma.audit.findMany({
      where,
      include: {
        user: { select: { id: true, email: true, name: true, profilePhoto: true } },
        reviewer: { select: { id: true, email: true } },
        branch: { include: { company: true } },
        company: true,
        answers: { include: { question: { include: { category: true } } } }
      },
      orderBy: { createdAt: 'desc' }
    });

    // Her denetim için skor hesapla
    const questions = await prisma.question.findMany({ include: { category: true } });

    const result = audits.map(audit => {
      const score = calculateScore(audit.answers, questions);
      return {
        id: audit.id,
        userId: audit.userId,
        title: audit.title || `Denetim #${audit.id}`,
        status: audit.status,
        createdAt: audit.createdAt,
        user: audit.user,
        reviewer: audit.reviewer,
        branch: audit.branch,
        company: audit.company,
        score
      };
    });

    res.json(result);
  } catch (error) {
    logger.error('Get audits error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// GET /audits/:id - Denetim detayı (Faz 4.1 validasyon)
app.get('/audits/:id', authenticate, validate(auditParamsSchema), async (req, res) => {
  try {
    const { id } = req.validated.params;

    const audit = await prisma.audit.findUnique({
      where: { id },
      include: {
        user: { select: { id: true, email: true, signatureUrl: true } },
        reviewer: { select: { id: true, email: true } },
        branch: { include: { company: true } },
        company: true,
        answers: { include: { question: { include: { category: true } } } },
        photos: { include: { question: true } }
      }
    });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    // Erişim kontrolü
    if (req.user.role.name === 'field' && audit.userId !== req.user.id) {
      return res.status(403).json({ error: 'Bu denetime erişim yetkiniz yok' });
    }

    if (req.user.role.name === 'firma_sahibi' && audit.companyId !== req.user.companyId) {
      return res.status(403).json({ error: 'Bu denetime erişim yetkiniz yok' });
    }

    if (req.user.role.name === 'sube_kullanici' && audit.branchId !== req.user.branchId) {
      return res.status(403).json({ error: 'Bu denetime erişim yetkiniz yok' });
    }

    const questions = await prisma.question.findMany({ include: { category: true } });
    const score = calculateScore(audit.answers, questions);

    res.json({ audit, score });
  } catch (error) {
    logger.error('Get audit error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits - Yeni denetim oluşturma ve denetçiye atama
// Sadece admin/planlamacı denetim oluşturabilir ve bir denetçiye (field) atar
app.post('/audits', authenticate, authorize('admin', 'planlamacı'), writeLimiter, async (req, res) => {
  try {
    const schema = z.object({
      userId: z.string({ required_error: 'Denetçi ID gerekli' }).uuid('Geçerli denetçi UUID gerekli'), // Atanacak denetçi (field)
      branchId: z.number({ required_error: 'Şube ID gerekli' }),
      title: z.string().optional(),
      scheduledDate: z.string().optional() // ISO date string
    });

    const data = schema.parse(req.body);

    // Atanacak kullanıcının field rolünde olduğunu kontrol et
    const targetUser = await prisma.user.findUnique({
      where: { id: data.userId },
      include: { role: true }
    });

    if (!targetUser) {
      return res.status(400).json({ error: 'Denetçi bulunamadı' });
    }

    if (targetUser.role.name !== 'field') {
      return res.status(400).json({ error: 'Denetim sadece saha denetçilerine atanabilir' });
    }

    // Şube'den şirket ID'sini al
    const branch = await prisma.branch.findUnique({ where: { id: data.branchId } });
    if (!branch) {
      return res.status(400).json({ error: 'Şube bulunamadı' });
    }

    const audit = await prisma.audit.create({
      data: {
        userId: data.userId,
        branchId: data.branchId,
        companyId: branch.companyId,
        title: data.title || `Denetim - ${branch.name}`,
        status: 'pending', // Atandı, denetçi başlatmasını bekliyor
        scheduledDate: data.scheduledDate ? new Date(data.scheduledDate) : null,
        assignedById: req.user.id // Atayan kişi
      },
      include: {
        user: { select: { id: true, email: true } },
        branch: { include: { company: true } }
      }
    });

    // Denetçiye bildirim gönder
    await prisma.notification.create({
      data: {
        userId: data.userId,
        title: 'Yeni Denetim Atandı',
        message: `"${audit.title}" denetimi size atandı. Şube: ${branch.name}`,
        type: 'audit_assigned',
        auditId: audit.id
      }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'CREATE',
      resource: 'Audit',
      resourceId: String(audit.id),
      newValue: { id: audit.id, title: audit.title, status: audit.status },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(201).json(audit);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    logger.error('Create audit error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/start - Denetçi denetimi başlatır (pending -> draft) (Faz 4.1 validasyon)
app.post('/audits/:id/start', authenticate, authorize('field', 'admin'), validate(auditParamsSchema), writeLimiter, async (req, res) => {
  try {
    const { id: auditId } = req.validated.params;

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    // Sadece atanan denetçi veya admin başlatabilir
    if (audit.userId !== req.user.id && req.user.role.name !== 'admin') {
      return res.status(403).json({ error: 'Bu denetim size atanmamış' });
    }

    if (audit.status !== 'pending') {
      return res.status(400).json({ error: 'Bu denetim zaten başlatılmış' });
    }

    const updated = await prisma.audit.update({
      where: { id: auditId },
      data: { status: 'draft', startedAt: new Date() },
      include: {
        user: { select: { id: true, email: true } },
        branch: { include: { company: true } }
      }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'UPDATE',
      resource: 'Audit',
      resourceId: String(auditId),
      oldValue: { status: audit.status },
      newValue: { status: 'draft' },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: 'Denetim başlatıldı'
    });

    res.json(updated);
  } catch (error) {
    logger.error('Start audit error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/answers - Cevap kaydetme (Faz 4.1 validasyon)
app.post('/audits/:id/answers', authenticate, validate(auditAnswersSchema), writeLimiter, async (req, res) => {
  try {
    const { id: auditId } = req.validated.params;
    const { items } = req.validated.body;

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    // Sadece denetim sahibi ve draft durumunda güncelleme yapabilir
    if (audit.userId !== req.user.id && req.user.role.name !== 'admin') {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }

    if (audit.status !== 'draft' && audit.status !== 'revision_requested') {
      return res.status(400).json({ error: 'Bu denetim düzenlenemez' });
    }

    // Cevapları upsert et
    for (const item of items) {
      await prisma.answer.upsert({
        where: { auditId_questionId: { auditId, questionId: item.questionId } },
        update: { value: item.value, note: item.note },
        create: { auditId, questionId: item.questionId, value: item.value, note: item.note }
      });
    }

    res.json({ message: 'Cevaplar kaydedildi' });
  } catch (error) {
    logger.error('Save answers error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/photos - Fotoğraf yükleme (1.5b sıkıştırma, 1.5c magic bytes) (Faz 4.5 uploadLimiter)
app.post('/audits/:id/photos', authenticate, uploadLimiter, validate(auditParamsSchema), uploadImagesOnly.single('file'), async (req, res) => {
  try {
    const { id: auditId } = req.validated.params;
    const questionId = req.body.questionId ? parseInt(req.body.questionId) : null;

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    if (audit.userId !== req.user.id && req.user.role.name !== 'admin') {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }

    if (!['draft', 'revision_requested'].includes(audit.status)) {
      return res.status(400).json({ error: 'Bu denetim durumunda fotoğraf yüklenemez' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'Dosya gerekli' });
    }

    const filePath = path.join(uploadsDir, req.file.filename);
    if (!checkMagicBytes(filePath, req.file.mimetype)) {
      fs.unlinkSync(filePath);
      return res.status(400).json({ error: 'Dosya içeriği bildirilen formatla uyuşmuyor' });
    }

    const compressedPath = await compressImage(filePath, { maxWidth: 1920, quality: 80, format: 'jpeg' });
    const filename = path.basename(compressedPath);

    const photo = await prisma.photo.create({
      data: {
        auditId,
        questionId,
        url: `/uploads/${filename}`
      }
    });

    res.status(201).json(photo);
  } catch (error) {
    if (req.file && req.file.filename) {
      try { fs.unlinkSync(path.join(uploadsDir, req.file.filename)); } catch (_) {}
    }
    logger.error('Upload photo error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/signature - İmza kaydetme (Faz 4.1 validasyon)
app.post('/audits/:id/signature', authenticate, validate(auditParamsSchema), writeLimiter, async (req, res) => {
  try {
    const { id: auditId } = req.validated.params;
    const { dataUrl, type } = req.body; // type: 'auditor' veya 'client'

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    if (audit.userId !== req.user.id && req.user.role.name !== 'admin') {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }

    // Base64 imzayı dosyaya kaydet
    const base64Data = dataUrl.replace(/^data:image\/\w+;base64,/, '');
    const filename = `signature-${auditId}-${type || 'auditor'}-${Date.now()}.png`;
    const filepath = path.join(uploadsDir, filename);

    fs.writeFileSync(filepath, base64Data, 'base64');

    const signatureUrl = `/uploads/${filename}`;

    // Denetimi güncelle
    const updateData = type === 'client'
      ? { clientSignatureUrl: signatureUrl }
      : { auditorSignatureUrl: signatureUrl };

    await prisma.audit.update({
      where: { id: auditId },
      data: updateData
    });

    res.json({ url: signatureUrl });
  } catch (error) {
    logger.error('Save signature error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/signature/use-profile - Profil imzasını denetime uygula
app.post('/audits/:id/signature/use-profile', authenticate, validate(auditParamsSchema), writeLimiter, async (req, res) => {
  try {
    const { id: auditId } = req.validated.params;

    if (!req.user.signatureUrl) {
      return res.status(400).json({ error: 'Profilde kayıtlı imza bulunamadı.' });
    }

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });
    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }
    if (audit.userId !== req.user.id && req.user.role.name !== 'admin') {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }

    await prisma.audit.update({
      where: { id: auditId },
      data: { auditorSignatureUrl: req.user.signatureUrl }
    });

    res.json({ url: req.user.signatureUrl });
  } catch (error) {
    logger.error('Use profile signature error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/signatures - Çift imza yükleme (1.5b sıkıştırma, 1.5c magic bytes) (Faz 4.5 uploadLimiter)
app.post('/audits/:id/signatures', authenticate, uploadLimiter, validate(auditParamsSchema), uploadImagesOnly.fields([{ name: 'auditorSignature' }, { name: 'clientSignature' }]), async (req, res) => {
  try {
    const { id: auditId } = req.validated.params;

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });
    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    if (audit.userId !== req.user.id && req.user.role.name !== 'admin') {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }

    const updateData = {};

    const processSignature = async (file) => {
      const filePath = path.join(uploadsDir, file.filename);
      if (!checkMagicBytes(filePath, file.mimetype)) {
        fs.unlinkSync(filePath);
        throw new Error('Dosya içeriği bildirilen formatla uyuşmuyor');
      }
      await compressImage(filePath, { maxWidth: 800, quality: 95, format: 'png' });
      return `/uploads/${path.basename(filePath)}`;
    };

    if (req.files['auditorSignature']) {
      const f = req.files['auditorSignature'][0];
      updateData.auditorSignatureUrl = await processSignature(f);
    }

    if (req.files['clientSignature']) {
      const f = req.files['clientSignature'][0];
      updateData.clientSignatureUrl = await processSignature(f);
    }

    if (Object.keys(updateData).length > 0) {
      await prisma.audit.update({
        where: { id: auditId },
        data: updateData
      });
    }

    res.json({ message: 'İmzalar kaydedildi', urls: updateData });
  } catch (error) {
    if (req.files) {
      for (const key of ['auditorSignature', 'clientSignature']) {
        if (req.files[key]) {
          try { fs.unlinkSync(path.join(uploadsDir, req.files[key][0].filename)); } catch (_) {}
        }
      }
    }
    logger.error('Save signatures error:', error);
    res.status(error.message?.includes('uyuşmuyor') ? 400 : 500).json({ error: error.message || 'Sunucu hatası' });
  }
});

// POST /audits/:id/submit - Denetimi gönderme (Faz 4.1 validasyon)
app.post('/audits/:id/submit', authenticate, validate(auditParamsSchema), writeLimiter, async (req, res) => {
  try {
    const { id: auditId } = req.validated.params;

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    if (audit.userId !== req.user.id && req.user.role.name !== 'admin') {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }

    if (!audit.auditorSignatureUrl || !audit.clientSignatureUrl) {
      return res.status(400).json({ error: 'Denetim gönderilemez: Her iki imza da gerekli.' });
    }

    const schema = z.object({
      authorizedPerson: z.string().min(1, 'Karşı taraf adı soyadı zorunludur.').trim()
    });
    const { authorizedPerson } = schema.parse(req.body);

    await prisma.audit.update({
      where: { id: auditId },
      data: { status: 'submitted', authorizedPerson, submittedAt: new Date() }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'UPDATE',
      resource: 'Audit',
      resourceId: String(auditId),
      oldValue: { status: audit.status },
      newValue: { status: 'submitted' },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: 'Denetim gönderildi'
    });

    res.json({ message: 'Denetim gönderildi' });
  } catch (error) {
    logger.error('Submit audit error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/review - Denetimi onaylama/reddetme (Faz 4.1 validasyon)
app.post('/audits/:id/review', authenticate, authorize('admin', 'gözden_geçiren', 'planlamacı'), validate(auditReviewSchema), writeLimiter, async (req, res) => {
  try {
    const { id: auditId } = req.validated.params;
    const { action, note } = req.validated.body;

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    if (audit.status !== 'submitted') {
      return res.status(400).json({ error: 'Bu denetim onay bekliyor durumunda değil' });
    }

    const newStatus = action === 'approve' ? 'approved' : 'revision_requested';
    const updateData = {
      status: newStatus,
      reviewerId: req.user.id,
      revisionNote: action === 'reject' ? note : null
    };
    if (action === 'approve') {
      updateData.approvedAt = new Date();
    } else {
      updateData.revisionRequestedAt = new Date();
    }

    await prisma.audit.update({
      where: { id: auditId },
      data: updateData
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'UPDATE',
      resource: 'Audit',
      resourceId: String(auditId),
      oldValue: { status: audit.status },
      newValue: { status: newStatus, reviewerId: req.user.id },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: action === 'approve' ? 'Denetim onaylandı' : `Revizyon talep edildi: ${note || ''}`
    });

    res.json({ message: action === 'approve' ? 'Denetim onaylandı' : 'Revizyon talep edildi' });
  } catch (error) {
    logger.error('Review audit error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /audits/:id - Denetim silme (soft delete) (Faz 4.1 validasyon)
app.delete('/audits/:id', authenticate, authorize('admin'), validate(auditParamsSchema), writeLimiter, async (req, res) => {
  try {
    const { id } = req.validated.params;

    const oldAudit = await prisma.audit.findUnique({ where: { id } });
    await prisma.audit.update({
      where: { id },
      data: {
        deletedAt: new Date(),
        deletedByUserId: req.user.id
      }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'DELETE',
      resource: 'Audit',
      resourceId: String(id),
      oldValue: oldAudit ? { id: oldAudit.id, title: oldAudit.title, status: oldAudit.status } : null,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({ message: 'Denetim silindi' });
  } catch (error) {
    logger.error('Delete audit error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/corrective-actions - Şube aksiyon bildirimi gönderme (Faz 4.1 validasyon)
app.post('/audits/:id/corrective-actions', authenticate, authorize('sube_kullanici', 'admin'), validate(auditCorrectiveActionsSchema), writeLimiter, async (req, res) => {
  try {
    const { id: auditId } = req.validated.params;
    const { actions } = req.validated.body;

    const audit = await prisma.audit.findUnique({
      where: { id: auditId },
      include: {
        user: { select: { id: true, email: true } },
        branch: { include: { company: true } },
        company: true
      }
    });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    // Şube kullanıcısı sadece kendi şubesinin denetimi için aksiyon alabilir
    if (req.user.role.name === 'sube_kullanici' && audit.branchId !== req.user.branchId) {
      return res.status(403).json({ error: 'Bu denetime erişim yetkiniz yok' });
    }

    // CorrectiveAction kayıtlarını oluştur
    for (const action of actions) {
      if (!action.description && (!action.photoUrls || action.photoUrls.length === 0)) continue;
      await prisma.correctiveAction.create({
        data: {
          auditId,
          questionId: action.questionId,
          description: action.description || '',
          status: 'in_progress',
          assignedTo: req.user.id
        }
      });
    }

    // Bildirim gönderilecek kullanıcıları bul:
    // 1) Denetimi yapan (field)
    // 2) Admin roller
    // 3) Planlamacı
    // 4) Firma sahibi (aynı şirkete bağlı)
    const notifyUsers = new Set();

    // Denetçiyi ekle
    if (audit.userId) notifyUsers.add(audit.userId);

    // Admin + Planlamacı + Gözden Geçiren rolleri
    const staffUsers = await prisma.user.findMany({
      where: { role: { name: { in: ['admin', 'planlamacı', 'gözden_geçiren'] } } },
      select: { id: true }
    });
    staffUsers.forEach(u => notifyUsers.add(u.id));

    // Firma sahibi (aynı şirkete bağlı)
    if (audit.branch?.company?.id || audit.companyId) {
      const companyId = audit.branch?.company?.id || audit.companyId;
      const firmaUsers = await prisma.user.findMany({
        where: { role: { name: 'firma_sahibi' }, companyId },
        select: { id: true }
      });
      firmaUsers.forEach(u => notifyUsers.add(u.id));
    }

    // Kendisine bildirim gönderme
    notifyUsers.delete(req.user.id);

    const auditTitle = audit.title || `Denetim #${auditId}`;
    const branchName = audit.branch?.name || '';

    for (const userId of notifyUsers) {
      await prisma.notification.create({
        data: {
          userId,
          title: 'Aksiyon Raporu Gönderildi',
          message: `"${auditTitle}" denetimine${branchName ? ' (' + branchName + ')' : ''} şube aksiyonları eklendi. ${actions.length} madde güncellendi.`,
          type: 'corrective_action',
          auditId
        }
      });
    }

    res.json({ message: 'Aksiyonlar kaydedildi ve merkeze bildirim gönderildi', count: actions.length });
  } catch (error) {
    logger.error('Corrective actions error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ STATS ENDPOINTS ============

// GET /stats/overview - Dashboard istatistikleri
app.get('/stats/overview', authenticate, async (req, res) => {
  try {
    let where = { deletedAt: null };

    if (req.user.role.name === 'field') {
      where.userId = req.user.id;
    }

    if (req.user.role.name === 'firma_sahibi' && req.user.companyId) {
      where.companyId = req.user.companyId;
    }

    if (req.user.role.name === 'sube_kullanici' && req.user.branchId) {
      where.branchId = req.user.branchId;
    }

    const total = await prisma.audit.count({ where });
    const draft = await prisma.audit.count({ where: { ...where, status: 'draft' } });
    const submitted = await prisma.audit.count({ where: { ...where, status: 'submitted' } });
    const approved = await prisma.audit.count({ where: { ...where, status: 'approved' } });
    const revision = await prisma.audit.count({ where: { ...where, status: 'revision_requested' } });

    const completionRate = total > 0 ? Math.round((approved / total) * 100) : 0;

    res.json({
      total,
      draft,
      submitted,
      approved,
      revision,
      completionRate
    });
  } catch (error) {
    logger.error('Get stats error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// GET /stats/annual - Yıllık grafik verisi
app.get('/stats/annual', authenticate, async (req, res) => {
  try {
    const currentYear = new Date().getFullYear();
    const months = [];

    // Rol bazlı filtreleme
    let roleFilter = {};
    if (req.user.role.name === 'field') {
      roleFilter.userId = req.user.id;
    }
    if (req.user.role.name === 'firma_sahibi' && req.user.companyId) {
      roleFilter.companyId = req.user.companyId;
    }
    if (req.user.role.name === 'sube_kullanici' && req.user.branchId) {
      roleFilter.branchId = req.user.branchId;
    }

    for (let month = 1; month <= 12; month++) {
      const startDate = new Date(currentYear, month - 1, 1);
      const endDate = new Date(currentYear, month, 0, 23, 59, 59);

      const audits = await prisma.audit.findMany({
        where: {
          deletedAt: null,
          status: 'approved',
          createdAt: { gte: startDate, lte: endDate },
          ...roleFilter
        },
        include: {
          answers: { include: { question: true } }
        }
      });

      // Ortalama puan hesapla
      const questions = await prisma.question.findMany();
      let totalPercent = 0;
      let count = 0;

      for (const audit of audits) {
        const score = calculateScore(audit.answers, questions);
        if (score.totalPoints > 0) {
          totalPercent += score.percent;
          count++;
        }
      }

      months.push({
        month,
        averageScore: count > 0 ? Math.round(totalPercent / count) : 0,
        auditCount: audits.length
      });
    }

    res.json(months);
  } catch (error) {
    logger.error('Get annual stats error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ PROFILE ENDPOINTS ============

// POST /profile/signature - Profil imza kaydetme (SVG veya PNG dataUrl)
app.post('/profile/signature', authenticate, validate(profileSignatureSchema), writeLimiter, async (req, res) => {
  try {
    const { dataUrl } = req.validated.body;
    const userId = req.user.id;
    const filename = `signature-profile-${userId}-${Date.now()}.png`;
    const filepath = path.join(uploadsDir, filename);

    if (dataUrl.startsWith('data:image/png;base64,')) {
      const base64Data = dataUrl.replace(/^data:image\/png;base64,/, '');
      fs.writeFileSync(filepath, base64Data, 'base64');
    } else if (dataUrl.startsWith('data:image/svg+xml')) {
      let svgBuffer;
      if (dataUrl.includes(';base64,')) {
        const base64Data = dataUrl.replace(/^data:image\/svg\+xml;base64,/, '');
        svgBuffer = Buffer.from(base64Data, 'base64');
      } else {
        const svgPart = dataUrl.replace(/^data:image\/svg\+xml,/, '');
        const decoded = decodeURIComponent(svgPart);
        svgBuffer = Buffer.from(decoded, 'utf8');
      }
      await sharp(svgBuffer)
        .png()
        .toFile(filepath);
    } else {
      return res.status(400).json({ error: 'Sadece PNG veya SVG formatı desteklenir' });
    }

    const signatureUrl = `/uploads/${filename}`;

    await prisma.user.update({
      where: { id: userId },
      data: { signatureUrl }
    });

    res.json({ url: signatureUrl, signatureUrl });
  } catch (error) {
    logger.error('Save profile signature error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// PUT /profile - Profil güncelleme (Faz 4.1 validasyon)
app.put('/profile', authenticate, validate(profileUpdateSchema), async (req, res) => {
  try {
    const { profilePhoto, signatureUrl } = req.validated.body;

    const oldUser = await prisma.user.findUnique({ where: { id: req.user.id } });
    const user = await prisma.user.update({
      where: { id: req.user.id },
      data: { profilePhoto, signatureUrl },
      include: { role: true }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'UPDATE',
      resource: 'Profile',
      resourceId: String(req.user.id),
      oldValue: oldUser ? { profilePhoto: oldUser.profilePhoto } : null,
      newValue: { profilePhoto: user.profilePhoto },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      id: user.id,
      email: user.email,
      role: user.role.name,
      profilePhoto: user.profilePhoto,
      signatureUrl: user.signatureUrl
    });
  } catch (error) {
    logger.error('Update profile error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// PUT /profile/password - Şifre değiştirme (Faz 2.2 şifre politikası)
app.put('/profile/password', authenticate, async (req, res) => {
  try {
    const schema = z.object({
      currentPassword: z.string().min(1, 'Mevcut şifre gerekli'),
      newPassword: passwordSchema
    });
    const { currentPassword, newPassword } = schema.parse(req.body);

    const user = await prismaWithPassword.user.findUnique({ where: { id: req.user.id } });

    const isValid = await bcrypt.compare(currentPassword, user.password);
    if (!isValid) {
      return res.status(400).json({ error: 'Mevcut şifre hatalı' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

    await prisma.user.update({
      where: { id: req.user.id },
      data: { password: hashedPassword }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'UPDATE',
      resource: 'Profile',
      resourceId: String(req.user.id),
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: 'Şifre değiştirildi'
    });

    res.json({ message: 'Şifre değiştirildi' });
  } catch (error) {
    logger.error('Change password error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ FILE UPLOAD ============

// POST /upload - Genel dosya yükleme (1.5b, 1.5c - PDF veya resim) (Faz 4.5 uploadLimiter)
app.post('/upload', authenticate, uploadLimiter, uploadWithPdf.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Dosya gerekli' });
    }

    const filePath = path.join(uploadsDir, req.file.filename);
    if (!checkMagicBytes(filePath, req.file.mimetype)) {
      fs.unlinkSync(filePath);
      return res.status(400).json({ error: 'Dosya içeriği bildirilen formatla uyuşmuyor' });
    }

    let filename = req.file.filename;
    if (ALLOWED_IMAGE_MIME.includes(req.file.mimetype)) {
      const compressedPath = await compressImage(filePath, { maxWidth: 1920, quality: 80, format: 'jpeg' });
      filename = path.basename(compressedPath);
    }

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'CREATE',
      resource: 'File',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: filename
    });

    res.json({ url: `/uploads/${filename}` });
  } catch (error) {
    if (req.file?.filename) {
      try { fs.unlinkSync(path.join(uploadsDir, req.file.filename)); } catch (_) {}
    }
    logger.error('Upload error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ NOTIFICATIONS ============

// Helper: Bildirim oluşturma
async function createNotification(userId, title, message, type, auditId = null) {
  return await prisma.notification.create({
    data: { userId, title, message, type, auditId }
  });
}

// GET /notifications - Kullanıcının bildirimleri
app.get('/notifications', authenticate, async (req, res) => {
  try {
    const notifications = await prisma.notification.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: 'desc' },
      take: 50
    });

    const unreadCount = await prisma.notification.count({
      where: { userId: req.user.id, read: false }
    });

    res.json({ notifications, unreadCount });
  } catch (error) {
    logger.error('Get notifications error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /notifications/:id/read - Bildirimi okundu işaretle (Faz 4.1 validasyon)
app.post('/notifications/:id/read', authenticate, validate(paramsOnlySchema), async (req, res) => {
  try {
    const { id } = req.validated.params;

    await prisma.notification.updateMany({
      where: { id, userId: req.user.id },
      data: { read: true }
    });

    res.json({ message: 'Bildirim okundu olarak işaretlendi' });
  } catch (error) {
    logger.error('Mark notification read error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /notifications/read-all - Tüm bildirimleri okundu işaretle
app.post('/notifications/read-all', authenticate, async (req, res) => {
  try {
    await prisma.notification.updateMany({
      where: { userId: req.user.id, read: false },
      data: { read: true }
    });

    res.json({ message: 'Tüm bildirimler okundu olarak işaretlendi' });
  } catch (error) {
    logger.error('Mark all notifications read error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ CORRECTIVE ACTIONS ============

// GET /corrective-actions - Düzeltici faaliyetleri listele
app.get('/corrective-actions', authenticate, async (req, res) => {
  try {
    const { status, auditId } = req.query;

    const where = {};
    if (status) where.status = status;
    if (auditId) where.auditId = auditId;

    // Rol bazlı filtreleme
    if (req.user.role.name === 'field') {
      const audits = await prisma.audit.findMany({
        where: { userId: req.user.id },
        select: { id: true }
      });
      where.auditId = { in: audits.map(a => a.id) };
    }

    const actions = await prisma.correctiveAction.findMany({
      where,
      include: {
        audit: { include: { branch: true } },
        question: true
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(actions);
  } catch (error) {
    logger.error('Get corrective actions error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /corrective-actions - Yeni düzeltici faaliyet oluştur (Faz 4.1 validasyon)
app.post('/corrective-actions', authenticate, authorize('admin', 'planlamacı', 'gözden_geçiren'), validate(correctiveActionCreateSchema), writeLimiter, async (req, res) => {
  try {
    const { auditId, questionId, description, assignedTo, dueDate } = req.validated.body;

    const action = await prisma.correctiveAction.create({
      data: {
        auditId,
        questionId,
        description,
        assignedTo,
        dueDate: dueDate ? new Date(dueDate) : null,
        status: 'open'
      },
      include: {
        audit: { include: { branch: true } },
        question: true
      }
    });

    // Bildirim gönder
    if (assignedTo) {
      await createNotification(
        assignedTo,
        'Yeni Düzeltici Faaliyet',
        `"${action.question.text}" için düzeltici faaliyet atandı.`,
        'action_assigned',
        auditId
      );
    }

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'CREATE',
      resource: 'CorrectiveAction',
      resourceId: String(action.id),
      newValue: { id: action.id, auditId, questionId },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(201).json(action);
  } catch (error) {
    logger.error('Create corrective action error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// PUT /corrective-actions/:id - Düzeltici faaliyeti güncelle (Faz 4.1 validasyon)
app.put('/corrective-actions/:id', authenticate, validate(correctiveActionUpdateSchema), writeLimiter, async (req, res) => {
  try {
    const { id } = req.validated.params;
    const { status, closedNote } = req.validated.body;

    // Erişim kontrolü: sadece admin, planlamacı, gözden_geçiren veya atanan kişi
    const existingAction = await prisma.correctiveAction.findUnique({
      where: { id },
      include: { audit: true }
    });

    if (!existingAction) {
      return res.status(404).json({ error: 'Düzeltici faaliyet bulunamadı' });
    }

    const allowedRoles = ['admin', 'planlamacı', 'gözden_geçiren'];
    const isAssigned = existingAction.assignedTo === req.user.id;
    const isAuditOwner = existingAction.audit?.userId === req.user.id;

    if (!allowedRoles.includes(req.user.role.name) && !isAssigned && !isAuditOwner) {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }

    const updateData = {};
    if (status) {
      updateData.status = status;
      if (status === 'closed') {
        updateData.closedAt = new Date();
        updateData.closedNote = closedNote;
      }
    }

    const action = await prisma.correctiveAction.update({
      where: { id },
      data: updateData,
      include: {
        audit: { include: { branch: true } },
        question: true
      }
    });

    createAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'UPDATE',
      resource: 'CorrectiveAction',
      resourceId: String(id),
      oldValue: { status: existingAction.status },
      newValue: { status: action.status },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json(action);
  } catch (error) {
    logger.error('Update corrective action error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ AUTO NOTIFICATION TRIGGERS ============

// Denetim atandığında bildirim gönderme (POST /audits sonrası)
// Bu fonksiyon POST /audits içinde çağrılmalı - yukarıda zaten var

// ============ PDF REPORTS ============

// GET /audits/:id/pdf - Genel PDF rapor (tüm sorular) (Faz 4.1 validasyon)
app.get('/audits/:id/pdf', authenticate, validate(auditParamsSchema), async (req, res) => {
  try {
    const { id: auditId } = req.validated.params;

    const audit = await prisma.audit.findUnique({
      where: { id: auditId },
      include: {
        user: { select: { email: true } },
        branch: { include: { company: true } },
        answers: { include: { question: { include: { category: true } } } },
        photos: true
      }
    });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    // Erişim kontrolü
    if (req.user.role.name === 'field' && audit.userId !== req.user.id) {
      return res.status(403).json({ error: 'Bu denetime erişim yetkiniz yok' });
    }
    if (req.user.role.name === 'firma_sahibi' && audit.companyId !== req.user.companyId) {
      return res.status(403).json({ error: 'Bu denetime erişim yetkiniz yok' });
    }
    if (req.user.role.name === 'sube_kullanici' && audit.branchId !== req.user.branchId) {
      return res.status(403).json({ error: 'Bu denetime erişim yetkiniz yok' });
    }

    // PDF oluştur
    const doc = new PDFDocument({ margin: 50 });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=denetim-${auditId}-genel.pdf`);
    doc.pipe(res);

    // Başlık
    doc.fontSize(20).text('DENETİM RAPORU', { align: 'center' });
    doc.moveDown();

    // Bilgiler
    doc.fontSize(12);
    doc.text(`Şirket: ${audit.branch?.company?.name || '-'}`);
    doc.text(`Şube: ${audit.branch?.name || '-'}`);
    doc.text(`Denetçi: ${audit.user?.email || '-'}`);
    doc.text(`Tarih: ${new Date(audit.createdAt).toLocaleDateString('tr-TR')}`);
    doc.text(`Durum: ${audit.status}`);
    doc.moveDown();

    // Kategorilere göre grupla
    const categories = {};
    for (const answer of audit.answers) {
      const catName = answer.question.category.title;
      if (!categories[catName]) categories[catName] = [];
      categories[catName].push(answer);
    }

    // Puan hesapla
    let totalPoints = 0;
    let earnedPoints = 0;
    for (const answer of audit.answers) {
      if (answer.value !== 'DD') {
        totalPoints += answer.question.points;
        if (answer.value === 'U') earnedPoints += answer.question.points;
        else if (answer.value === 'YP') earnedPoints += answer.question.points / 2;
      }
    }
    const percentage = totalPoints > 0 ? Math.round((earnedPoints / totalPoints) * 100) : 0;

    doc.fontSize(14).text(`TOPLAM PUAN: ${percentage}%`, { align: 'center' });
    doc.moveDown();

    // Sorular
    for (const [catName, answers] of Object.entries(categories)) {
      doc.fontSize(14).text(catName, { underline: true });
      doc.moveDown(0.5);

      for (const answer of answers) {
        const statusMap = { U: 'Uygun', UD: 'Uygun Değil', YP: 'Yarım Puan', DD: 'Kapsam Dışı' };
        doc.fontSize(10);
        doc.text(`• ${answer.question.text}`);
        doc.text(`  Cevap: ${statusMap[answer.value] || answer.value}`, { continued: answer.note ? true : false });
        if (answer.note) doc.text(` - Not: ${answer.note}`);
      }
      doc.moveDown();
    }

    // İmzalar
    doc.moveDown(2);
    doc.fontSize(12).text('İMZALAR', { align: 'center' });
    doc.moveDown();
    doc.text('Denetçi: ____________________          Karşı Taraf: ____________________');

    doc.end();
  } catch (error) {
    logger.error('Generate PDF error:', error);
    res.status(500).json({ error: 'PDF oluşturulamadı' });
  }
});

// GET /audits/:id/pdf-nonconformity - Uygunsuzluk raporu (sadece UD cevaplar) (Faz 4.1 validasyon)
app.get('/audits/:id/pdf-nonconformity', authenticate, validate(auditParamsSchema), async (req, res) => {
  try {
    const { id: auditId } = req.validated.params;

    const audit = await prisma.audit.findUnique({
      where: { id: auditId },
      include: {
        user: { select: { email: true } },
        branch: { include: { company: true } },
        answers: {
          where: { value: 'UD' },
          include: { question: { include: { category: true } } }
        },
        photos: true
      }
    });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    // Erişim kontrolü
    if (req.user.role.name === 'field' && audit.userId !== req.user.id) {
      return res.status(403).json({ error: 'Bu denetime erişim yetkiniz yok' });
    }
    if (req.user.role.name === 'firma_sahibi' && audit.companyId !== req.user.companyId) {
      return res.status(403).json({ error: 'Bu denetime erişim yetkiniz yok' });
    }
    if (req.user.role.name === 'sube_kullanici' && audit.branchId !== req.user.branchId) {
      return res.status(403).json({ error: 'Bu denetime erişim yetkiniz yok' });
    }

    // PDF oluştur
    const doc = new PDFDocument({ margin: 50 });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=denetim-${auditId}-uygunsuzluk.pdf`);
    doc.pipe(res);

    // Başlık
    doc.fontSize(20).text('UYGUNSUZLUK RAPORU', { align: 'center' });
    doc.moveDown();

    // Bilgiler
    doc.fontSize(12);
    doc.text(`Şirket: ${audit.branch?.company?.name || '-'}`);
    doc.text(`Şube: ${audit.branch?.name || '-'}`);
    doc.text(`Denetçi: ${audit.user?.email || '-'}`);
    doc.text(`Tarih: ${new Date(audit.createdAt).toLocaleDateString('tr-TR')}`);
    doc.moveDown();

    doc.fontSize(14).text(`TOPLAM UYGUNSUZLUK: ${audit.answers.length} adet`, { align: 'center' });
    doc.moveDown();

    // Uygunsuz sorular
    let index = 1;
    for (const answer of audit.answers) {
      doc.fontSize(12).text(`${index}. ${answer.question.text}`, { underline: true });
      doc.fontSize(10);
      doc.text(`   Kategori: ${answer.question.category.title}`);
      if (answer.note) {
        doc.text(`   Açıklama: ${answer.note}`);
      }
      doc.moveDown();
      index++;
    }

    // İmzalar
    doc.moveDown(2);
    doc.fontSize(12).text('İMZALAR', { align: 'center' });
    doc.moveDown();
    doc.text('Denetçi: ____________________          Karşı Taraf: ____________________');
    doc.moveDown();
    doc.text('Tarih: ____________________');

    doc.end();
  } catch (error) {
    logger.error('Generate PDF nonconformity error:', error);
    res.status(500).json({ error: 'PDF oluşturulamadı' });
  }
});

// GET /stats/branch/:id - Şube bazlı istatistikler (Faz 4.1 validasyon)
app.get('/stats/branch/:id', authenticate, validate(paramsOnlySchema), async (req, res) => {
  try {
    const { id: branchId } = req.validated.params;

    const branch = await prisma.branch.findUnique({
      where: { id: branchId },
      include: { company: true }
    });

    if (!branch) {
      return res.status(404).json({ error: 'Şube bulunamadı' });
    }

    // Erişim kontrolü
    if (req.user.role.name === 'field') {
      const assignment = await prisma.branchAssignment.findFirst({
        where: { branchId, userId: req.user.id }
      });
      if (!assignment) {
        return res.status(403).json({ error: 'Bu şubeye erişim yetkiniz yok' });
      }
    }
    if (req.user.role.name === 'firma_sahibi' && branch.companyId !== req.user.companyId) {
      return res.status(403).json({ error: 'Bu şubeye erişim yetkiniz yok' });
    }
    if (req.user.role.name === 'sube_kullanici' && branchId !== req.user.branchId) {
      return res.status(403).json({ error: 'Bu şubeye erişim yetkiniz yok' });
    }

    // Son 12 ay denetimler
    const audits = await prisma.audit.findMany({
      where: {
        branchId,
        deletedAt: null,
        status: { in: ['approved', 'submitted'] }
      },
      include: {
        user: { select: { email: true } },
        answers: { include: { question: true } }
      },
      orderBy: { createdAt: 'desc' },
      take: 50
    });

    // Her denetim için puan hesapla
    const auditStats = audits.map(audit => {
      let totalPoints = 0;
      let earnedPoints = 0;
      for (const answer of audit.answers) {
        if (answer.value !== 'DD') {
          totalPoints += answer.question.points;
          if (answer.value === 'U') earnedPoints += answer.question.points;
          else if (answer.value === 'YP') earnedPoints += answer.question.points / 2;
        }
      }
      return {
        id: audit.id,
        date: audit.createdAt,
        auditor: audit.user?.email,
        score: totalPoints > 0 ? Math.round((earnedPoints / totalPoints) * 100) : 0,
        status: audit.status
      };
    });

    res.json({
      branch,
      totalAudits: audits.length,
      averageScore: auditStats.length > 0
        ? Math.round(auditStats.reduce((a, b) => a + b.score, 0) / auditStats.length)
        : 0,
      audits: auditStats
    });
  } catch (error) {
    logger.error('Branch stats error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ 404 ve Global Error Handler - 1.4 ============

app.use((req, res) => {
  res.status(404).json({ error: 'İstenen kaynak bulunamadı' });
});

app.use((err, req, res, next) => {
  if (err.name === 'ZodError') {
    return res.status(400).json({
      error: 'Doğrulama hatası',
      details: err.errors.map(e => ({ field: e.path.join('.'), message: e.message }))
    });
  }
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({ error: 'Bu kaynak için erişim izniniz yok' });
  }
  // Faz 4.4: Prisma hata kodları merkezi işleme
  if (err.code === 'P2002') {
    return res.status(409).json({ error: 'Bu kayıt zaten mevcut' });
  }
  if (err.code === 'P2025') {
    return res.status(404).json({ error: 'Kayıt bulunamadı' });
  }
  const isProduction = process.env.NODE_ENV === 'production';
  logger.error('Unhandled error:', err);
  res.status(err.status || 500).json({
    error: isProduction ? 'Sunucu hatası' : err.message,
    ...(isProduction ? {} : { stack: err.stack })
  });
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});

// ============ SERVER START ============

async function ensureAdminUser() {
  const count = await prisma.user.count();
  if (count > 0) return;
  logger.info('Veritabanında kullanıcı yok, varsayılan admin oluşturuluyor...');
  let adminRole = await prisma.role.findUnique({ where: { name: 'admin' } });
  if (!adminRole) {
    adminRole = await prisma.role.create({ data: { name: 'admin' } });
  }
  const hashedPassword = await bcrypt.hash('!Admin123456', 10);
  await prisma.user.create({
    data: {
      name: 'Admin Kullanıcı',
      email: 'admin@admin.com',
      password: hashedPassword,
      roleId: adminRole.id
    }
  });
  logger.info('admin@admin.com / !Admin123456 kullanıcısı oluşturuldu');
}

ensureAdminUser()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 TeftişPro Backend sunucusu http://0.0.0.0:${PORT} adresinde çalışıyor`);
    });
  })
  .catch((err) => {
    console.error('Sunucu başlatma hatası:', err);
    process.exit(1);
  });
