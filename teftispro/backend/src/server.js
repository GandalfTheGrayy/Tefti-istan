// TeftişPro - Backend Server
// Teftiş ve Kalite Kontrol Uygulaması API

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { PrismaClient } = require('@prisma/client');
const { z } = require('zod');
const PDFDocument = require('pdfkit');

const prisma = new PrismaClient();
const app = express();

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'teftispro-super-secret-key-2024';
const PORT = process.env.PORT || 3636;

// Uploads klasörü
const uploadsDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer konfigürasyonu
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB limit

// Middleware
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(morgan('dev'));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(uploadsDir));

// Rate Limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: 200,
  message: { error: 'Çok fazla istek. Lütfen daha sonra tekrar deneyin.' }
});

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 dakika
  max: 20,
  message: { error: 'Çok fazla giriş denemesi. Lütfen daha sonra tekrar deneyin.' }
});

app.use(generalLimiter);

// ============ HELPER FUNCTIONS ============

// JWT Token oluşturma
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role.name },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

// JWT Token doğrulama middleware
async function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Yetkilendirme token\'ı gerekli' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      include: { role: true }
    });

    if (!user) {
      return res.status(401).json({ error: 'Kullanıcı bulunamadı' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Geçersiz token' });
  }
}

// Rol kontrolü middleware
function authorize(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role.name)) {
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

// POST /auth/login - Kullanıcı girişi
app.post('/auth/login', loginLimiter, async (req, res) => {
  try {
    const schema = z.object({
      email: z.string().email('Geçerli bir e-posta adresi girin'),
      password: z.string().min(1, 'Şifre gerekli')
    });

    const { email, password } = schema.parse(req.body);

    const user = await prisma.user.findUnique({
      where: { email },
      include: { role: true }
    });

    if (!user) {
      return res.status(401).json({ error: 'E-posta veya şifre hatalı' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'E-posta veya şifre hatalı' });
    }

    const token = generateToken(user);

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role.name,
        profilePhoto: user.profilePhoto,
        companyId: user.companyId,
        branchId: user.branchId
      }
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    console.error('Login error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
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
      email: u.email,
      role: u.role.name,
      profilePhoto: u.profilePhoto,
      companyId: u.companyId,
      branchId: u.branchId,
      createdAt: u.createdAt
    })));
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /users - Yeni kullanıcı oluşturma
app.post('/users', authenticate, authorize('admin'), async (req, res) => {
  try {
    const schema = z.object({
      email: z.string().email('Geçerli bir e-posta adresi girin'),
      password: z.string().min(6, 'Şifre en az 6 karakter olmalı'),
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

    const hashedPassword = await bcrypt.hash(data.password, 10);

    const user = await prisma.user.create({
      data: {
        email: data.email,
        password: hashedPassword,
        roleId: role.id,
        companyId: data.companyId,
        branchId: data.branchId
      },
      include: { role: true }
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
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /users/:id - Kullanıcı silme
app.delete('/users/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    await prisma.user.delete({ where: { id } });

    res.json({ message: 'Kullanıcı silindi' });
  } catch (error) {
    console.error('Delete user error:', error);
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
    console.error('Get companies error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /companies - Yeni şirket oluşturma
app.post('/companies', authenticate, authorize('admin'), async (req, res) => {
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

    res.status(201).json(company);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    console.error('Create company error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// PUT /companies/:id - Şirket güncelleme
app.put('/companies/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { name, logoUrl, ownerId } = req.body;

    const company = await prisma.company.update({
      where: { id },
      data: { name, logoUrl, ownerId },
      include: { owner: { select: { id: true, email: true } } }
    });

    res.json(company);
  } catch (error) {
    console.error('Update company error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /companies/:id - Şirket silme
app.delete('/companies/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    await prisma.company.delete({ where: { id } });

    res.json({ message: 'Şirket silindi' });
  } catch (error) {
    console.error('Delete company error:', error);
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
    console.error('Get regions error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /regions - Yeni bölge oluşturma
app.post('/regions', authenticate, authorize('admin'), async (req, res) => {
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

    res.status(201).json(region);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    console.error('Create region error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /regions/:id - Bölge silme
app.delete('/regions/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    await prisma.region.delete({ where: { id } });

    res.json({ message: 'Bölge silindi' });
  } catch (error) {
    console.error('Delete region error:', error);
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
    console.error('Get branches error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /branches - Yeni şube oluşturma
app.post('/branches', authenticate, authorize('admin'), async (req, res) => {
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

    res.status(201).json(branch);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    console.error('Create branch error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// PUT /branches/:id - Şube güncelleme
app.put('/branches/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { name, city, address, phone, email, regionId, isActive } = req.body;

    const branch = await prisma.branch.update({
      where: { id },
      data: { name, city, address, phone, email, regionId, isActive },
      include: { company: true, region: true }
    });

    res.json(branch);
  } catch (error) {
    console.error('Update branch error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /branches/:id - Şube silme
app.delete('/branches/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    await prisma.branch.delete({ where: { id } });

    res.json({ message: 'Şube silindi' });
  } catch (error) {
    console.error('Delete branch error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /branches/:id/assign - Denetçi atama
app.post('/branches/:id/assign', authenticate, authorize('admin', 'planlamacı'), async (req, res) => {
  try {
    const branchId = parseInt(req.params.id);
    const { userId } = req.body;

    const assignment = await prisma.branchAssignment.create({
      data: { branchId, userId },
      include: { branch: true, user: { select: { id: true, email: true } } }
    });

    res.status(201).json(assignment);
  } catch (error) {
    console.error('Assign branch error:', error);
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
    console.error('Get categories error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /categories - Yeni kategori oluşturma
app.post('/categories', authenticate, authorize('admin'), async (req, res) => {
  try {
    const schema = z.object({
      title: z.string().min(1, 'Kategori başlığı gerekli')
    });

    const data = schema.parse(req.body);

    const category = await prisma.category.create({
      data,
      include: { questions: true }
    });

    res.status(201).json(category);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    console.error('Create category error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /categories/:id - Kategori silme
app.delete('/categories/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    await prisma.category.delete({ where: { id } });

    res.json({ message: 'Kategori silindi' });
  } catch (error) {
    console.error('Delete category error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ QUESTIONS ENDPOINTS ============

// POST /questions - Yeni soru oluşturma
app.post('/questions', authenticate, authorize('admin'), async (req, res) => {
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

    res.status(201).json(question);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    console.error('Create question error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /questions/:id - Soru silme
app.delete('/questions/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    await prisma.question.delete({ where: { id } });

    res.json({ message: 'Soru silindi' });
  } catch (error) {
    console.error('Delete question error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ AUDITS ENDPOINTS ============

// GET /audits - Denetim listesi
app.get('/audits', authenticate, async (req, res) => {
  try {
    const { status } = req.query;

    let where = { deletedAt: null };

    // Field kullanıcı sadece kendi denetimlerini görür
    if (req.user.role.name === 'field') {
      where.userId = req.user.id;
    }

    // Firma sahibi sadece kendi şirketinin denetimlerini görür
    if (req.user.role.name === 'firma_sahibi') {
      if (req.user.companyId) {
        where.companyId = req.user.companyId;
      }
    }

    // Şube kullanıcısı sadece kendi şubesinin denetimlerini görür
    if (req.user.role.name === 'sube_kullanici' && req.user.branchId) {
      where.branchId = req.user.branchId;
    }

    if (status) {
      where.status = status;
    }

    const audits = await prisma.audit.findMany({
      where,
      include: {
        user: { select: { id: true, email: true } },
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
    console.error('Get audits error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// GET /audits/:id - Denetim detayı
app.get('/audits/:id', authenticate, async (req, res) => {
  try {
    const id = parseInt(req.params.id);

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
    console.error('Get audit error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits - Yeni denetim oluşturma ve denetçiye atama
// Sadece admin/planlamacı denetim oluşturabilir ve bir denetçiye (field) atar
app.post('/audits', authenticate, authorize('admin', 'planlamacı'), async (req, res) => {
  try {
    const schema = z.object({
      userId: z.number({ required_error: 'Denetçi ID gerekli' }), // Atanacak denetçi (field)
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

    res.status(201).json(audit);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.errors[0].message });
    }
    console.error('Create audit error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/start - Denetçi denetimi başlatır (pending -> draft)
app.post('/audits/:id/start', authenticate, authorize('field'), async (req, res) => {
  try {
    const auditId = parseInt(req.params.id);

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    // Sadece atanan denetçi başlatabilir
    if (audit.userId !== req.user.id) {
      return res.status(403).json({ error: 'Bu denetim size atanmamış' });
    }

    if (audit.status !== 'pending') {
      return res.status(400).json({ error: 'Bu denetim zaten başlatılmış' });
    }

    const updated = await prisma.audit.update({
      where: { id: auditId },
      data: { status: 'draft' },
      include: {
        user: { select: { id: true, email: true } },
        branch: { include: { company: true } }
      }
    });

    res.json(updated);
  } catch (error) {
    console.error('Start audit error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/answers - Cevap kaydetme
app.post('/audits/:id/answers', authenticate, async (req, res) => {
  try {
    const auditId = parseInt(req.params.id);

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

    const { items } = req.body;

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
    console.error('Save answers error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/photos - Fotoğraf yükleme
app.post('/audits/:id/photos', authenticate, upload.single('file'), async (req, res) => {
  try {
    const auditId = parseInt(req.params.id);
    const questionId = req.body.questionId ? parseInt(req.body.questionId) : null;

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    if (audit.userId !== req.user.id && req.user.role.name !== 'admin') {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }

    // Status kontrolü: sadece draft veya revision_requested durumunda fotoğraf yüklenebilir
    if (!['draft', 'revision_requested'].includes(audit.status)) {
      return res.status(400).json({ error: 'Bu denetim durumunda fotoğraf yüklenemez' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'Dosya gerekli' });
    }

    const photo = await prisma.photo.create({
      data: {
        auditId,
        questionId,
        url: `/uploads/${req.file.filename}`
      }
    });

    res.status(201).json(photo);
  } catch (error) {
    console.error('Upload photo error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/signature - İmza kaydetme
app.post('/audits/:id/signature', authenticate, async (req, res) => {
  try {
    const auditId = parseInt(req.params.id);
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
    console.error('Save signature error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/signatures - Çift imza yükleme (FormData)
app.post('/audits/:id/signatures', authenticate, upload.fields([{ name: 'auditorSignature' }, { name: 'clientSignature' }]), async (req, res) => {
  try {
    const auditId = parseInt(req.params.id);

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });
    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    // Erişim kontrolü: sadece denetim sahibi veya admin
    if (audit.userId !== req.user.id && req.user.role.name !== 'admin') {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }

    const updateData = {};

    if (req.files['auditorSignature']) {
      updateData.auditorSignatureUrl = `/uploads/${req.files['auditorSignature'][0].filename}`;
    }

    if (req.files['clientSignature']) {
      updateData.clientSignatureUrl = `/uploads/${req.files['clientSignature'][0].filename}`;
    }

    if (Object.keys(updateData).length > 0) {
      await prisma.audit.update({
        where: { id: auditId },
        data: updateData
      });
    }

    res.json({ message: 'İmzalar kaydedildi', urls: updateData });
  } catch (error) {
    console.error('Save signatures error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/submit - Denetimi gönderme
app.post('/audits/:id/submit', authenticate, async (req, res) => {
  try {
    const auditId = parseInt(req.params.id);

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    if (audit.userId !== req.user.id && req.user.role.name !== 'admin') {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }

    await prisma.audit.update({
      where: { id: auditId },
      data: { status: 'submitted' }
    });

    res.json({ message: 'Denetim gönderildi' });
  } catch (error) {
    console.error('Submit audit error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /audits/:id/review - Denetimi onaylama/reddetme
app.post('/audits/:id/review', authenticate, authorize('admin', 'gözden_geçiren', 'planlamacı'), async (req, res) => {
  try {
    const auditId = parseInt(req.params.id);
    const { action, note } = req.body; // action: 'approve' veya 'reject'

    const audit = await prisma.audit.findUnique({ where: { id: auditId } });

    if (!audit) {
      return res.status(404).json({ error: 'Denetim bulunamadı' });
    }

    if (audit.status !== 'submitted') {
      return res.status(400).json({ error: 'Bu denetim onay bekliyor durumunda değil' });
    }

    const newStatus = action === 'approve' ? 'approved' : 'revision_requested';

    await prisma.audit.update({
      where: { id: auditId },
      data: {
        status: newStatus,
        reviewerId: req.user.id,
        revisionNote: action === 'reject' ? note : null
      }
    });

    res.json({ message: action === 'approve' ? 'Denetim onaylandı' : 'Revizyon talep edildi' });
  } catch (error) {
    console.error('Review audit error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// DELETE /audits/:id - Denetim silme (soft delete)
app.delete('/audits/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    await prisma.audit.update({
      where: { id },
      data: { deletedAt: new Date() }
    });

    res.json({ message: 'Denetim silindi' });
  } catch (error) {
    console.error('Delete audit error:', error);
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
    console.error('Get stats error:', error);
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
    console.error('Get annual stats error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ PROFILE ENDPOINTS ============

// PUT /profile - Profil güncelleme
app.put('/profile', authenticate, async (req, res) => {
  try {
    const { profilePhoto, signatureUrl } = req.body;

    const user = await prisma.user.update({
      where: { id: req.user.id },
      data: { profilePhoto, signatureUrl },
      include: { role: true }
    });

    res.json({
      id: user.id,
      email: user.email,
      role: user.role.name,
      profilePhoto: user.profilePhoto,
      signatureUrl: user.signatureUrl
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// PUT /profile/password - Şifre değiştirme
app.put('/profile/password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await prisma.user.findUnique({ where: { id: req.user.id } });

    const isValid = await bcrypt.compare(currentPassword, user.password);
    if (!isValid) {
      return res.status(400).json({ error: 'Mevcut şifre hatalı' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id: req.user.id },
      data: { password: hashedPassword }
    });

    res.json({ message: 'Şifre değiştirildi' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ FILE UPLOAD ============

// POST /upload - Genel dosya yükleme
app.post('/upload', authenticate, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Dosya gerekli' });
    }

    res.json({ url: `/uploads/${req.file.filename}` });
  } catch (error) {
    console.error('Upload error:', error);
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
    console.error('Get notifications error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /notifications/:id/read - Bildirimi okundu işaretle
app.post('/notifications/:id/read', authenticate, async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    await prisma.notification.updateMany({
      where: { id, userId: req.user.id },
      data: { read: true }
    });

    res.json({ message: 'Bildirim okundu olarak işaretlendi' });
  } catch (error) {
    console.error('Mark notification read error:', error);
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
    console.error('Mark all notifications read error:', error);
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
    if (auditId) where.auditId = parseInt(auditId);

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
    console.error('Get corrective actions error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// POST /corrective-actions - Yeni düzeltici faaliyet oluştur
app.post('/corrective-actions', authenticate, authorize('admin', 'planlamacı', 'gözden_geçiren'), async (req, res) => {
  try {
    const { auditId, questionId, description, assignedTo, dueDate } = req.body;

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

    res.status(201).json(action);
  } catch (error) {
    console.error('Create corrective action error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// PUT /corrective-actions/:id - Düzeltici faaliyeti güncelle
app.put('/corrective-actions/:id', authenticate, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { status, closedNote } = req.body;

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

    res.json(action);
  } catch (error) {
    console.error('Update corrective action error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ AUTO NOTIFICATION TRIGGERS ============

// Denetim atandığında bildirim gönderme (POST /audits sonrası)
// Bu fonksiyon POST /audits içinde çağrılmalı - yukarıda zaten var

// ============ PDF REPORTS ============

// GET /audits/:id/pdf - Genel PDF rapor (tüm sorular)
app.get('/audits/:id/pdf', authenticate, async (req, res) => {
  try {
    const auditId = parseInt(req.params.id);

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
    console.error('Generate PDF error:', error);
    res.status(500).json({ error: 'PDF oluşturulamadı' });
  }
});

// GET /audits/:id/pdf-nonconformity - Uygunsuzluk raporu (sadece UD cevaplar)
app.get('/audits/:id/pdf-nonconformity', authenticate, async (req, res) => {
  try {
    const auditId = parseInt(req.params.id);

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
    console.error('Generate PDF nonconformity error:', error);
    res.status(500).json({ error: 'PDF oluşturulamadı' });
  }
});

// GET /stats/branch/:id - Şube bazlı istatistikler
app.get('/stats/branch/:id', authenticate, async (req, res) => {
  try {
    const branchId = parseInt(req.params.id);

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
    console.error('Branch stats error:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ============ SERVER START ============

app.listen(PORT, () => {
  console.log(`🚀 TeftişPro Backend sunucusu http://localhost:${PORT} adresinde çalışıyor`);
});
