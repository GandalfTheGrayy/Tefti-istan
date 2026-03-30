# TeftişPro — ISO/IEC 27001:2022 Güvenlik Uyumluluk Rehberi

> **Proje:** TeftişPro - Teftiş ve Kalite Kontrol Uygulaması  
> **Standart:** ISO/IEC 27001:2022 (Ek A Teknolojik Kontroller)  
> **Oluşturulma Tarihi:** 2026-03-03  
> **Son Güncelleme:** 2026-03-03

---

## İçindekiler

- [Mevcut Durum Analizi](#mevcut-durum-analizi)
- [Faz 1 — Kritik Güvenlik Açıklarının Kapatılması (Acil)](#faz-1--kritik-güvenlik-açıklarının-kapatılması-acil)
- [Faz 2 — Kimlik Doğrulama ve Oturum Güvenliği](#faz-2--kimlik-doğrulama-ve-oturum-güvenliği)
- [Faz 3 — Frontend Güvenliği (XSS, CSRF, CSP)](#faz-3--frontend-güvenliği-xss-csrf-csp)
- [Faz 4 — Backend Güvenliği ve Kriptografik Kontroller](#faz-4--backend-güvenliği-ve-kriptografik-kontroller)
- [Faz 5 — Loglama, İzleme ve Denetim İzleri](#faz-5--loglama-i̇zleme-ve-denetim-i̇zleri)
- [Faz 6 — CI/CD ve Güvenlik Test Altyapısı](#faz-6--cicd-ve-güvenlik-test-altyapısı)
- [Faz 7 — Bulut, Altyapı ve Dağıtım Güvenliği](#faz-7--bulut-altyapı-ve-dağıtım-güvenliği)
- [Faz 8 — İş Sürekliliği ve Felaket Kurtarma](#faz-8--i̇ş-sürekliliği-ve-felaket-kurtarma)

---

## Mevcut Durum Analizi

### Teknoloji Yığını

| Katman | Teknoloji | Versiyon |
|--------|-----------|----------|
| Backend | Node.js + Express | 4.21.1 |
| ORM | Prisma | 5.22.0 |
| Veritabanı | SQLite | `file:./dev.db` |
| Frontend | Vanilla JS + Tailwind (CDN) | - |
| Build | Vite | 5.4.0 |
| Auth | JWT + bcryptjs | 9.0.2 / 2.4.3 |

### Mevcut Güvenlik Kontrolleri

| Kontrol | Durum | Notlar |
|---------|-------|--------|
| Helmet HTTP Header'ları | Kısmen | `crossOriginResourcePolicy: false` — CSP yapılandırması yok |
| CORS | Zayıf | `origin: true` tüm domain'lere izin veriyor |
| Rate Limiting | Temel | Genel: 200/15dk, Login: 20/10dk |
| Şifre Hashleme | Aktif | bcrypt 10 round |
| JWT Kimlik Doğrulama | Aktif | 24 saat süre, Bearer token |
| Rol Tabanlı Yetkilendirme | Aktif | 6 rol: admin, planlamacı, field, gözden_geçiren, firma_sahibi, sube_kullanici |
| Girdi Doğrulama (Zod) | Kısmen | Bazı endpoint'lerde eksik |
| Dosya Boyutu Limiti | Aktif | Multer 10MB |

### Kritik Güvenlik Bulguları

| # | Bulgu | Risk | Konum |
|---|-------|------|-------|
| 1 | JWT_SECRET hardcoded | **Kritik** | `server.js:22` — `'teftispro-super-secret-key-2024'` |
| 2 | CORS tüm origin'lere açık | **Yüksek** | `server.js:43` — `cors({ origin: true })` |
| 3 | JWT localStorage'da saklanıyor | **Yüksek** | `login.html:259` — XSS ile çalınabilir |
| 4 | CSP header'ı yok | **Yüksek** | XSS saldırılarına karşı savunmasız |
| 5 | Body limit 50MB | **Orta** | `server.js:45` — DoS riski |
| 6 | Global error handler yok | **Orta** | Stack trace sızma riski |
| 7 | Dosya tipi doğrulaması yok | **Orta** | Multer'da sadece boyut kontrolü |
| 8 | Şifre karmaşıklık politikası yok | **Orta** | `server.js:255` — `min(6)` yetersiz |
| 9 | Denetim izi (audit trail) yok | **Orta** | Veri değişiklikleri izlenmiyor |
| 10 | HTTPS zorunluluğu yok | **Yüksek** | Production'da MitM riski |
| 11 | CSRF koruması yok | **Orta** | SameSite cookie kullanılmıyor |
| 12 | Hesap kilitleme yok | **Orta** | Brute-force saldırısına açık |
| 13 | Demo hesap bilgileri HTML'de | **Düşük** | `login.html:171-204` — Production'da kaldırılmalı |
| 14 | `uploads/` dizini herkese açık | **Orta** | `server.js:47` — Yetki kontrolü yok |
| 15 | CI/CD ve güvenlik tarama yok | **Yüksek** | SAST/DAST/SCA araçları eksik |

---

## Faz 1 — Kritik Güvenlik Açıklarının Kapatılması (Acil)

> **ISO Referansları:** Ek A 8.28 (Güvenli Kodlama), Ek A 8.9 (Yapılandırma Yönetimi), Ek A 8.24 (Kriptografi Kullanımı)  
> **Öncelik:** Kritik  
> **Tahmini Süre:** 3-5 gün

### 1.1 Ortam Değişkenleri ve Sır Yönetimi

**Sorun:** JWT_SECRET kaynak kodda hardcoded. Kod deposuna erişen herkes tüm JWT token'ları forge edebilir.

```
// server.js:22 — MEVCUT (GÜVENSİZ)
const JWT_SECRET = process.env.JWT_SECRET || 'teftispro-super-secret-key-2024';
```

**Yapılacaklar:**

- [ ] `.env` dosyası oluştur (`.gitignore`'a eklenmiş olduğundan emin ol)
- [ ] `.env.example` şablonu oluştur (gerçek değerler olmadan)
- [ ] Fallback secret'ı kaldır, değişken yoksa uygulama başlatılmasın
- [ ] `dotenv` paketini kur

**`.env.example` dosyası:**

```env
# Server
PORT=3636
NODE_ENV=development

# JWT — Production'da en az 64 karakter rastgele string kullanın
# Oluşturmak için: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
JWT_SECRET=
JWT_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=7d

# Database
DATABASE_URL="file:./dev.db"

# CORS — Virgülle ayrılmış izin verilen origin'ler
ALLOWED_ORIGINS=http://localhost:2525

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100
LOGIN_RATE_LIMIT_WINDOW_MS=900000
LOGIN_RATE_LIMIT_MAX=5
```

**Güncellenmiş kod:**

```javascript
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET ortam değişkeni tanımlı değil. Uygulama başlatılamıyor.');
  process.exit(1);
}
```

### 1.2 CORS Yapılandırması

**Sorun:** `cors({ origin: true })` tüm domain'lerden gelen isteklere izin veriyor.

```
// server.js:43 — MEVCUT (GÜVENSİZ)
app.use(cors({ origin: true, credentials: true }));
```

**Yapılacaklar:**

- [ ] İzin verilen origin'leri `.env` dosyasından oku
- [ ] Production'da yalnızca kendi domain'inize izin ver
- [ ] Credentials ile birlikte wildcard origin kullanma

```javascript
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS politikası tarafından engellendi'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600
}));
```

### 1.3 Body Limit Düşürme

**Sorun:** `express.json({ limit: '50mb' })` — Büyük payload'larla DoS saldırısı riski.

**Yapılacaklar:**

- [ ] Genel body limiti 1MB'a düşür
- [ ] Fotoğraf/imza yükleme endpoint'leri için ayrı limit belirle (Multer zaten 10MB)

```javascript
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
```

### 1.4 Global Error Handler

**Sorun:** Her route kendi try/catch bloğunu kullanıyor. Yakalanmayan bir hata stack trace sızdırabilir.

**Yapılacaklar:**

- [ ] Merkezi hata yakalama middleware'i ekle
- [ ] Production'da stack trace'leri gizle
- [ ] Zod validation hatalarını merkezi olarak işle

```javascript
// server.js — Tüm route tanımlamalarından SONRA ekle

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'İstenen kaynak bulunamadı' });
});

// Global error handler
app.use((err, req, res, next) => {
  // Zod validation hatası
  if (err.name === 'ZodError') {
    return res.status(400).json({
      error: 'Doğrulama hatası',
      details: err.errors.map(e => ({ field: e.path.join('.'), message: e.message }))
    });
  }

  // CORS hatası
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({ error: 'Bu kaynak için erişim izniniz yok' });
  }

  // Production'da detay gösterme
  const isProduction = process.env.NODE_ENV === 'production';
  console.error('Unhandled error:', err);

  res.status(err.status || 500).json({
    error: isProduction ? 'Sunucu hatası' : err.message,
    ...(isProduction ? {} : { stack: err.stack })
  });
});

// Uncaught exception ve unhandled rejection
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});
```

### 1.5 Dosya Yükleme Güvenliği

**Sorun:** Multer'da dosya tipi doğrulaması yok. Zararlı dosya (`.exe`, `.php`, `.sh`) yüklenebilir.

**Yapılacaklar:**

- [ ] MIME type whitelist ekle
- [ ] Dosya uzantısı kontrolü ekle
- [ ] Dosya adı sanitizasyonu

```javascript
const ALLOWED_MIME_TYPES = [
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'application/pdf'
];

const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf'];

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (ALLOWED_MIME_TYPES.includes(file.mimetype) && ALLOWED_EXTENSIONS.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Desteklenmeyen dosya formatı. İzin verilen: JPG, PNG, GIF, WebP, PDF'), false);
  }
};

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB (10MB'dan düşürüldü)
  fileFilter
});
```

### 1.6 Helmet ve CSP Yapılandırması

**Sorun:** Helmet varsayılan ayarlarla çalışıyor, CSP tanımlı değil.

**Yapılacaklar:**

- [ ] Content Security Policy header'ı tanımla
- [ ] X-Frame-Options, X-Content-Type-Options vb. ayarla
- [ ] crossOriginResourcePolicy'yi doğru yapılandır

```javascript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.tailwindcss.com"],
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
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));
```

### 1.7 HTTPS Yönlendirmesi (Production)

**Yapılacaklar:**

- [ ] Production ortamında HTTP isteklerini HTTPS'e yönlendir

```javascript
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, `https://${req.hostname}${req.url}`);
    }
    next();
  });
}
```

### 1.8 Upload Dizini Erişim Kontrolü

**Sorun:** `/uploads` dizini herkese açık static olarak sunuluyor.

**Yapılacaklar:**

- [ ] Upload dosyalarına erişimi authenticate middleware ile koru

```javascript
// MEVCUT (GÜVENSİZ):
// app.use('/uploads', express.static(uploadsDir));

// YENİ: Kimlik doğrulamalı dosya erişimi
app.use('/uploads', authenticate, express.static(uploadsDir));
```

### Faz 1 Kontrol Listesi

- [ ] `dotenv` paketi kuruldu ve `.env` / `.env.example` oluşturuldu
- [ ] JWT_SECRET fallback kaldırıldı, zorunlu hale getirildi
- [ ] CORS belirli origin'lerle sınırlandırıldı
- [ ] Body limit 1MB'a düşürüldü
- [ ] Global error handler eklendi (stack trace gizleme dahil)
- [ ] Multer file filter eklendi (MIME + uzantı whitelist)
- [ ] Helmet CSP yapılandırması tamamlandı
- [ ] HTTPS yönlendirmesi eklendi (production)
- [ ] Upload dizini erişim kontrolü eklendi
- [ ] Demo hesap bilgileri production build'den çıkarıldı

---

## Faz 2 — Kimlik Doğrulama ve Oturum Güvenliği

> **ISO Referansları:** Ek A 5.17 (Kimlik Doğrulama Bilgileri), Ek A 8.5 (Güvenli Kimlik Doğrulama), Ek A 8.24 (Kriptografi Kullanımı)  
> **Öncelik:** Yüksek  
> **Tahmini Süre:** 5-7 gün

### 2.1 JWT Token'ı HttpOnly Cookie'ye Taşıma

**Sorun:** JWT token `localStorage`'da saklanıyor. Başarılı bir XSS saldırısı `document.cookie` veya `localStorage.getItem('token')` ile token'ı çalabilir.

**Yapılacaklar:**

- [ ] Login endpoint'i token'ı `Set-Cookie` header'ı ile göndersin
- [ ] Frontend'den `Authorization` header yerine cookie otomatik gönderilsin
- [ ] `authenticate` middleware cookie'den token okusun
- [ ] Logout endpoint'i cookie'yi temizlesin

**Backend — Login Response:**

```javascript
app.post('/auth/login', loginLimiter, async (req, res) => {
  // ... mevcut doğrulama mantığı ...

  const token = generateToken(user);
  const refreshToken = generateRefreshToken(user);

  // HttpOnly cookie olarak set et
  res.cookie('access_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 1000, // 1 saat
    path: '/'
  });

  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 gün
    path: '/auth/refresh'
  });

  res.json({
    user: {
      id: user.id,
      email: user.email,
      role: user.role.name,
      profilePhoto: user.profilePhoto,
      companyId: user.companyId,
      branchId: user.branchId
    }
  });
});
```

**Backend — Authenticate Middleware (güncellenmiş):**

```javascript
const cookieParser = require('cookie-parser');
app.use(cookieParser());

async function authenticate(req, res, next) {
  try {
    // Önce cookie'den, yoksa Authorization header'dan oku
    const token = req.cookies?.access_token ||
      (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.split(' ')[1] : null);

    if (!token) {
      return res.status(401).json({ error: 'Kimlik doğrulama gerekli' });
    }

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
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Oturum süresi doldu', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Geçersiz token' });
  }
}
```

**Frontend — Login (güncellenmiş):**

```javascript
const response = await fetch(`${API_URL}/auth/login`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include', // Cookie gönderimi için
  body: JSON.stringify({ email, password })
});

const data = await response.json();
if (!response.ok) throw new Error(data.error || 'Giriş başarısız');

// Token artık localStorage'da DEĞİL, cookie'de
localStorage.setItem('user', JSON.stringify(data.user));
window.location.href = '/public/kontrol_paneli.html';
```

**Frontend — API İstekleri (güncellenmiş):**

```javascript
// Tüm fetch isteklerinde credentials: 'include' ekle
const response = await fetch(`${API_URL}/endpoint`, {
  method: 'GET',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' }
});
```

### 2.2 Şifre Karmaşıklık Politikası

**Sorun:** Mevcut minimum şifre uzunluğu 6 karakter (`server.js:255`). ISO 27001 için yetersiz.

**Yapılacaklar:**

- [ ] Minimum 12 karakter, büyük/küçük harf, rakam, özel karakter zorunluluğu
- [ ] Yaygın şifreler listesi kontrolü (breached password check)
- [ ] bcrypt round'u 10'dan 12'ye artır

```javascript
const passwordSchema = z.string()
  .min(12, 'Şifre en az 12 karakter olmalı')
  .regex(/[A-Z]/, 'Şifre en az bir büyük harf içermeli')
  .regex(/[a-z]/, 'Şifre en az bir küçük harf içermeli')
  .regex(/[0-9]/, 'Şifre en az bir rakam içermeli')
  .regex(/[^A-Za-z0-9]/, 'Şifre en az bir özel karakter içermeli');

const BCRYPT_ROUNDS = 12;

// Kullanıcı oluşturma ve şifre değiştirme'de kullan
const hashedPassword = await bcrypt.hash(data.password, BCRYPT_ROUNDS);
```

### 2.3 Hesap Kilitleme Mekanizması

**Sorun:** Başarısız giriş denemesi sayısında bir üst sınır yok. Brute-force saldırısına açık.

**Yapılacaklar:**

- [ ] Başarısız giriş denemelerini takip et
- [ ] 5 başarısız deneme sonrası 15 dakika kilitle
- [ ] Kilitleme durumunu veritabanında sakla

**Prisma schema'ya ekle:**

```prisma
model User {
  // ... mevcut alanlar ...
  failedLoginAttempts Int       @default(0)
  lockedUntil         DateTime?
}
```

**Login endpoint'ine ekle:**

```javascript
app.post('/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = schema.parse(req.body);

  const user = await prisma.user.findUnique({
    where: { email },
    include: { role: true }
  });

  if (!user) {
    return res.status(401).json({ error: 'E-posta veya şifre hatalı' });
  }

  // Kilitleme kontrolü
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    const remainingMinutes = Math.ceil((user.lockedUntil - new Date()) / 60000);
    return res.status(423).json({
      error: `Hesap kilitli. ${remainingMinutes} dakika sonra tekrar deneyin.`
    });
  }

  const isValid = await bcrypt.compare(password, user.password);

  if (!isValid) {
    const attempts = user.failedLoginAttempts + 1;
    const updateData = { failedLoginAttempts: attempts };

    if (attempts >= 5) {
      updateData.lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 dk
      updateData.failedLoginAttempts = 0;
    }

    await prisma.user.update({ where: { id: user.id }, data: updateData });
    return res.status(401).json({ error: 'E-posta veya şifre hatalı' });
  }

  // Başarılı giriş — sayacı sıfırla
  await prisma.user.update({
    where: { id: user.id },
    data: { failedLoginAttempts: 0, lockedUntil: null }
  });

  // ... token oluşturma ve cookie set etme ...
});
```

### 2.4 Token Süresi ve Refresh Token

**Sorun:** JWT süresi 24 saat — çalınan bir token uzun süre geçerli kalır.

**Yapılacaklar:**

- [ ] Access token süresini 1 saate düşür
- [ ] Refresh token mekanizması ekle (7 gün)
- [ ] Token yenileme endpoint'i oluştur

```javascript
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role.name, type: 'access' },
    JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    { id: user.id, type: 'refresh' },
    JWT_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
  );
}

// Refresh endpoint
app.post('/auth/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies?.refresh_token;
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token bulunamadı' });
    }

    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    if (decoded.type !== 'refresh') {
      return res.status(401).json({ error: 'Geçersiz token tipi' });
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      include: { role: true }
    });

    if (!user) {
      return res.status(401).json({ error: 'Kullanıcı bulunamadı' });
    }

    const newAccessToken = generateToken(user);

    res.cookie('access_token', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000,
      path: '/'
    });

    res.json({ message: 'Token yenilendi' });
  } catch (error) {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return res.status(401).json({ error: 'Oturum süresi doldu, tekrar giriş yapın' });
  }
});
```

### 2.5 Logout Endpoint

**Yapılacaklar:**

- [ ] Sunucu taraflı logout endpoint'i oluştur
- [ ] Cookie'leri temizle

```javascript
app.post('/auth/logout', (req, res) => {
  res.clearCookie('access_token', { path: '/' });
  res.clearCookie('refresh_token', { path: '/auth/refresh' });
  res.json({ message: 'Çıkış yapıldı' });
});
```

### 2.6 Login Rate Limit Sıkılaştırma

**Yapılacaklar:**

- [ ] Login rate limit'ini 5 deneme / 15 dakikaya düşür

```javascript
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: 5,
  message: { error: 'Çok fazla giriş denemesi. 15 dakika sonra tekrar deneyin.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.body?.email || req.ip // E-posta bazlı limit
});
```

### Faz 2 Kontrol Listesi

- [ ] `cookie-parser` paketi kuruldu
- [ ] JWT token'ı HttpOnly + Secure + SameSite cookie'ye taşındı
- [ ] Frontend tüm fetch isteklerinde `credentials: 'include'` kullanıyor
- [ ] `localStorage`'dan token kaldırıldı (sadece user bilgisi saklanıyor)
- [ ] Şifre karmaşıklık politikası uygulandı (min 12 karakter + karma)
- [ ] bcrypt round 12'ye artırıldı
- [ ] Hesap kilitleme mekanizması aktif (5 deneme = 15 dk kilit)
- [ ] Access token süresi 1 saat, refresh token 7 gün
- [ ] `/auth/refresh` endpoint'i oluşturuldu
- [ ] `/auth/logout` endpoint'i oluşturuldu (cookie temizleme)
- [ ] Login rate limit 5/15dk'ya sıkılaştırıldı

---

## Faz 3 — Frontend Güvenliği (XSS, CSRF, CSP)

> **ISO Referansları:** Ek A 8.28 (Güvenli Kodlama), Ek A 8.12 (Veri Sızıntısını Önleme)  
> **Öncelik:** Yüksek  
> **Tahmini Süre:** 5-7 gün

### 3.1 XSS Koruması — DOMPurify Entegrasyonu

**Sorun:** Kullanıcı girdileri (denetim notları, açıklamalar vb.) HTML olarak render edilebilir. Stored XSS riski.

**Yapılacaklar:**

- [ ] DOMPurify kütüphanesini projeye ekle
- [ ] Kullanıcıdan gelen tüm verileri render etmeden önce sanitize et
- [ ] `innerHTML` kullanımlarını `textContent` ile değiştir (mümkün olan yerlerde)

```html
<!-- Her HTML sayfasının <head> bölümüne ekle -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"
        integrity="sha384-..." crossorigin="anonymous"></script>
```

```javascript
// Yardımcı fonksiyon — tüm sayfalarda kullanılacak
function safeHTML(dirty) {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'br', 'p', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: []
  });
}

function safeText(dirty) {
  const div = document.createElement('div');
  div.textContent = dirty;
  return div.innerHTML;
}

// Kullanım örneği
// YANLIŞ: element.innerHTML = userInput;
// DOĞRU:  element.textContent = userInput;
// DOĞRU:  element.innerHTML = safeHTML(userInput);
```

### 3.2 innerHTML Kullanımlarının Denetimi

**Yapılacaklar:**

- [ ] Tüm frontend dosyalarında `innerHTML` kullanımlarını tara
- [ ] Kullanıcı girdisi içeren innerHTML'leri `textContent` veya `safeHTML()` ile değiştir
- [ ] Template literal'lardaki kullanıcı verilerini escape et

```javascript
// MEVCUT (XSS RİSKİ):
row.innerHTML = `<td>${audit.title}</td><td>${audit.user.email}</td>`;

// GÜVENLİ ALTERNATİF 1 — textContent:
const tdTitle = document.createElement('td');
tdTitle.textContent = audit.title;
row.appendChild(tdTitle);

// GÜVENLİ ALTERNATİF 2 — safeHTML:
row.innerHTML = `<td>${safeText(audit.title)}</td><td>${safeText(audit.user.email)}</td>`;
```

### 3.3 Anti-CSRF Token Mekanizması

**Sorun:** Cookie tabanlı kimlik doğrulamaya geçildiğinde CSRF saldırısı riski artar.

**Yapılacaklar:**

- [ ] CSRF token üretme endpoint'i oluştur
- [ ] Her state-changing isteğe (POST, PUT, DELETE) CSRF token ekle
- [ ] Backend'de CSRF token doğrula

**Backend — CSRF token üretimi:**

```javascript
const crypto = require('crypto');

// CSRF token oluştur ve cookie'ye yaz
app.get('/auth/csrf-token', (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex');

  res.cookie('csrf_token', csrfToken, {
    httpOnly: false,  // Frontend JavaScript tarafından okunabilir olmalı
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 1000
  });

  res.json({ csrfToken });
});

// CSRF doğrulama middleware
function validateCSRF(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const cookieToken = req.cookies?.csrf_token;
  const headerToken = req.headers['x-csrf-token'];

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'Geçersiz CSRF token' });
  }

  next();
}

// Authenticate'den sonra, route'lardan önce ekle
app.use(validateCSRF);
```

**Frontend — CSRF token gönderimi:**

```javascript
// Sayfa yüklendiğinde CSRF token al
async function getCSRFToken() {
  const res = await fetch('/api/auth/csrf-token', { credentials: 'include' });
  const data = await res.json();
  return data.csrfToken;
}

// Her state-changing isteğe ekle
async function securedFetch(url, options = {}) {
  const csrfToken = document.cookie
    .split('; ')
    .find(row => row.startsWith('csrf_token='))
    ?.split('=')[1];

  return fetch(url, {
    ...options,
    credentials: 'include',
    headers: {
      ...options.headers,
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken || ''
    }
  });
}
```

### 3.4 Subresource Integrity (SRI)

**Sorun:** CDN'den yüklenen kaynaklar (Tailwind, Google Fonts, Material Icons) değiştirilebilir.

**Yapılacaklar:**

- [ ] Tüm CDN kaynaklarına SRI hash'leri ekle
- [ ] Uzun vadede Tailwind CSS'i lokal build'e taşı

```html
<!-- Mevcut (güvensiz): -->
<script src="https://cdn.tailwindcss.com"></script>

<!-- SRI ile (kısa vadeli çözüm): -->
<script src="https://cdn.tailwindcss.com"
        integrity="sha384-HASH_VALUE_HERE"
        crossorigin="anonymous"></script>

<!-- Uzun vadeli çözüm: Tailwind'i lokal olarak derle -->
<!-- npm install -D tailwindcss && npx tailwindcss -o public/tailwind.min.css -->
<link rel="stylesheet" href="/public/tailwind.min.css">
```

### 3.5 Tailwind CSS Lokal Build'e Geçiş

**Yapılacaklar:**

- [ ] `tailwindcss` paketini frontend'e kur
- [ ] `tailwind.config.js` oluştur
- [ ] Build script'i ekle
- [ ] CDN `<script>` etiketini kaldır

```bash
cd teftispro/frontend
npm install -D tailwindcss
npx tailwindcss init
```

```javascript
// tailwind.config.js
module.exports = {
  content: ['./public/**/*.html', './public/**/*.js'],
  theme: {
    extend: {
      fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] }
    }
  }
};
```

```json
// package.json scripts'e ekle:
"build:css": "tailwindcss -i ./src/input.css -o ./public/tailwind.min.css --minify"
```

### Faz 3 Kontrol Listesi

- [ ] DOMPurify entegre edildi, `safeHTML()` / `safeText()` yardımcı fonksiyonları oluşturuldu
- [ ] Tüm `innerHTML` kullanımları denetlendi ve güvenli alternatiflere geçildi
- [ ] Anti-CSRF token mekanizması backend ve frontend'de uygulandı
- [ ] CDN kaynaklarına SRI hash'leri eklendi
- [ ] Tailwind CSS lokal build'e geçirildi (CDN kaldırıldı)
- [ ] Üçüncü taraf script'ler minimize edildi ve envanteri çıkarıldı

---

## Faz 4 — Backend Güvenliği ve Kriptografik Kontroller

> **ISO Referansları:** Ek A 8.24 (Kriptografi Kullanımı), Ek A 8.11 (Veri Maskeleme), Ek A 8.28 (Güvenli Kodlama)  
> **Öncelik:** Orta-Yüksek  
> **Tahmini Süre:** 7-10 gün

### 4.1 Tüm Endpoint'lerde Zod Validasyon Zorunluluğu

**Sorun:** Bazı endpoint'lerde (PUT /companies/:id, PUT /branches/:id, PUT /corrective-actions/:id, PUT /profile, vb.) girdi doğrulaması yapılmıyor.

**Yapılacaklar:**

- [ ] Validasyon eksik olan tüm endpoint'leri tespit et ve Zod şeması ekle
- [ ] `parseInt(req.params.id)` kullanımlarında NaN kontrolü ekle
- [ ] Merkezi validasyon middleware'i oluştur

```javascript
// Merkezi validasyon middleware
function validate(schema) {
  return (req, res, next) => {
    try {
      req.validated = schema.parse({
        body: req.body,
        params: req.params,
        query: req.query
      });
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Doğrulama hatası',
          details: error.errors.map(e => ({
            field: e.path.join('.'),
            message: e.message
          }))
        });
      }
      next(error);
    }
  };
}

// Parametre ID doğrulama yardımcısı
function parseId(value) {
  const id = parseInt(value, 10);
  if (isNaN(id) || id <= 0) {
    throw new Error('Geçersiz ID');
  }
  return id;
}
```

**Eksik validasyona sahip endpoint örnekleri:**

```javascript
// PUT /companies/:id — Zod şeması EKLE
const updateCompanySchema = z.object({
  body: z.object({
    name: z.string().min(1).optional(),
    logoUrl: z.string().url().optional().nullable(),
    ownerId: z.number().int().positive().optional().nullable()
  }),
  params: z.object({
    id: z.string().transform(v => parseId(v))
  })
});

// PUT /profile/password — newPassword validasyonu EKLE
const changePasswordSchema = z.object({
  body: z.object({
    currentPassword: z.string().min(1, 'Mevcut şifre gerekli'),
    newPassword: passwordSchema // Faz 2'deki karmaşıklık şeması
  })
});
```

### 4.2 SQL Injection Koruması Doğrulaması

**Durum:** Prisma ORM kullanıldığı için parametreli sorgular otomatik uygulanıyor. Ancak `$queryRaw` veya `$executeRaw` kullanımı kontrole alınmalı.

**Yapılacaklar:**

- [ ] Kod tabanında `$queryRaw`, `$executeRaw`, `$queryRawUnsafe` araması yap
- [ ] Varsa parametreli sorguya dönüştür
- [ ] Prisma query logging'i aktif et (development)

```javascript
// Prisma'da güvenli raw query kullanımı:
// GÜVENSİZ: prisma.$queryRawUnsafe(`SELECT * FROM User WHERE email = '${email}'`)
// GÜVENLİ:  prisma.$queryRaw`SELECT * FROM User WHERE email = ${email}`
```

### 4.3 Hassas Veri Maskeleme (Ek A 8.11)

**Sorun:** API yanıtlarında gereksiz bilgi ifşa edilebilir (password hash, createdAt vb.).

**Yapılacaklar:**

- [ ] User model'den `password` alanını API yanıtlarından her zaman çıkar
- [ ] Prisma global middleware ile hassas alan filtreleme
- [ ] Log'lara hassas veri yazılmasını engelle

```javascript
// Prisma middleware — password alanını otomatik çıkar
prisma.$use(async (params, next) => {
  const result = await next(params);

  if (params.model === 'User') {
    if (Array.isArray(result)) {
      result.forEach(user => { delete user.password; });
    } else if (result && typeof result === 'object') {
      delete result.password;
    }
  }

  return result;
});
```

### 4.4 API Yanıtlarında Bilgi İfşası Önleme

**Yapılacaklar:**

- [ ] Express sunucu imzasını gizle
- [ ] Detaylı hata mesajlarını production'da kısıtla

```javascript
// Express sunucu imzasını gizle
app.disable('x-powered-by');

// Prisma hata mesajlarını kullanıcıya gösterme
// Mevcut: console.error('Create user error:', error);
// SORUN: Prisma hatası kullanıcıya sızabilir

// Her catch bloğunda:
catch (error) {
  if (error.code === 'P2002') {
    return res.status(409).json({ error: 'Bu kayıt zaten mevcut' });
  }
  if (error.code === 'P2025') {
    return res.status(404).json({ error: 'Kayıt bulunamadı' });
  }
  console.error(`[${new Date().toISOString()}] Error:`, error);
  res.status(500).json({ error: 'İşlem sırasında bir hata oluştu' });
}
```

### 4.5 Rate Limiting Genişletme

**Yapılacaklar:**

- [ ] API endpoint gruplarına özel rate limit'ler ekle
- [ ] Dosya yükleme endpoint'ine sıkı limit koy

```javascript
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Çok fazla dosya yükleme denemesi.' }
});

const writeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Çok fazla yazma işlemi.' }
});

// Uygulanacak yerlere örnek:
app.post('/upload', authenticate, uploadLimiter, upload.single('file'), ...);
app.post('/audits', authenticate, authorize('admin', 'planlamacı'), writeLimiter, ...);
```

### 4.6 server.js Modüler Yapıya Dönüştürme

**Sorun:** Tüm backend mantığı tek bir 1890 satırlık `server.js` dosyasında. Bakım ve güvenlik denetimi zor.

**Yapılacaklar:**

- [ ] Route'ları ayrı dosyalara böl
- [ ] Middleware'leri ayrı dosyalara taşı
- [ ] Validasyon şemalarını ayrı modüle al

**Hedef yapı:**

```
backend/src/
├── server.js              # Ana giriş (app setup + middleware)
├── config/
│   └── index.js           # Ortam değişkenleri ve konfigürasyon
├── middleware/
│   ├── authenticate.js    # JWT doğrulama
│   ├── authorize.js       # Rol kontrolü
│   ├── validate.js        # Zod validasyon middleware
│   ├── errorHandler.js    # Global hata yönetimi
│   └── csrf.js            # CSRF koruması
├── routes/
│   ├── auth.js            # /auth/*
│   ├── users.js           # /users/*
│   ├── companies.js       # /companies/*
│   ├── regions.js         # /regions/*
│   ├── branches.js        # /branches/*
│   ├── categories.js      # /categories/*
│   ├── questions.js       # /questions/*
│   ├── audits.js          # /audits/*
│   ├── stats.js           # /stats/*
│   ├── profile.js         # /profile/*
│   ├── notifications.js   # /notifications/*
│   └── uploads.js         # /upload
├── schemas/
│   ├── auth.schema.js
│   ├── user.schema.js
│   └── audit.schema.js
└── utils/
    ├── scoring.js         # Puan hesaplama
    └── pdf.js             # PDF oluşturma
```

### 4.7 TLS 1.2+ Zorunluluğu

**Yapılacaklar:**

- [ ] Production'da HTTPS sunucu yapılandırması veya reverse proxy (nginx) arkasına al
- [ ] TLS 1.0 ve 1.1'i devre dışı bırak
- [ ] HSTS header'ı aktif et (Faz 1'de yapıldı)

```javascript
// Eğer Node.js doğrudan HTTPS sunacaksa:
const https = require('https');
const tls = require('tls');

if (process.env.NODE_ENV === 'production') {
  const httpsServer = https.createServer({
    key: fs.readFileSync(process.env.TLS_KEY_PATH),
    cert: fs.readFileSync(process.env.TLS_CERT_PATH),
    minVersion: 'TLSv1.2',
    ciphers: [
      'TLS_AES_128_GCM_SHA256',
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256'
    ].join(':')
  }, app);

  httpsServer.listen(443, () => {
    console.log('HTTPS sunucusu 443 portunda çalışıyor');
  });
}
```

### Faz 4 Kontrol Listesi

- [ ] Tüm endpoint'lere Zod validasyon şeması eklendi
- [ ] Merkezi validasyon middleware oluşturuldu
- [ ] `$queryRaw` / `$executeRaw` kullanımı kontrol edildi
- [ ] Prisma middleware ile password alanı API yanıtlarından çıkarıldı
- [ ] `x-powered-by` header'ı kaldırıldı
- [ ] Prisma hata kodları merkezi olarak işleniyor
- [ ] Endpoint bazlı rate limit'ler tanımlandı
- [ ] `server.js` modüler yapıya dönüştürüldü
- [ ] TLS 1.2+ yapılandırması hazırlandı

---

## Faz 5 — Loglama, İzleme ve Denetim İzleri

> **ISO Referansları:** Ek A 8.15 (Loglama), Ek A 8.16 (İzleme Faaliyetleri), Ek A 8.17 (Saat Senkronizasyonu)  
> **Öncelik:** Orta  
> **Tahmini Süre:** 7-10 gün

### 5.1 Yapılandırılmış JSON Loglama (Morgan -> Winston/Pino)

**Sorun:** Morgan sadece HTTP isteklerini `dev` formatında logluyor. Yapılandırılmış, aranabilir, ISO uyumlu log üretmiyor.

**Yapılacaklar:**

- [ ] `winston` veya `pino` paketini kur
- [ ] JSON formatında yapılandırılmış log üret
- [ ] Log seviyelerini yapılandır (error, warn, info, debug)
- [ ] Dosya ve konsol transport'ları ayarla

```bash
npm install winston winston-daily-rotate-file
```

```javascript
const winston = require('winston');
require('winston-daily-rotate-file');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'teftispro-api' },
  transports: [
    // Hata logları ayrı dosyada
    new winston.transports.DailyRotateFile({
      filename: 'logs/error-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      maxSize: '20m',
      maxFiles: '365d',  // 12 ay saklama (ISO 27001 gereksinimi)
      zippedArchive: true
    }),
    // Tüm loglar
    new winston.transports.DailyRotateFile({
      filename: 'logs/combined-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '50m',
      maxFiles: '365d',
      zippedArchive: true
    })
  ]
});

// Development'da konsola da yaz
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

module.exports = logger;
```

**Express ile entegrasyon:**

```javascript
const expressWinston = require('express-winston');

// HTTP request logging (Morgan yerine)
app.use(expressWinston.logger({
  winstonInstance: logger,
  meta: true,
  msg: 'HTTP {{req.method}} {{req.url}} {{res.statusCode}} {{res.responseTime}}ms',
  expressFormat: false,
  colorize: false,
  dynamicMeta: (req) => ({
    userId: req.user?.id || null,
    userEmail: req.user?.email || null,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  })
}));
```

### 5.2 Denetim İzi (Audit Trail) Sistemi

**Sorun:** Veri oluşturma, güncelleme ve silme işlemleri loglanmıyor. Kim, ne zaman, neyi değiştirdi izlenemiyor.

**Yapılacaklar:**

- [ ] Prisma schema'ya `AuditLog` modeli ekle
- [ ] Prisma middleware ile otomatik denetim izi oluştur
- [ ] Kritik işlemleri logla

**Prisma schema'ya ekle:**

```prisma
model AuditLog {
  id          Int      @id @default(autoincrement())
  timestamp   DateTime @default(now())
  userId      Int?
  userEmail   String?
  action      String   // CREATE, UPDATE, DELETE, LOGIN, LOGIN_FAILED, LOGOUT, ACCESS_DENIED
  resource    String   // User, Audit, Company, Branch, vb.
  resourceId  String?
  oldValue    String?  // JSON — değişiklik öncesi
  newValue    String?  // JSON — değişiklik sonrası
  ipAddress   String?
  userAgent   String?
  details     String?  // Ek açıklama
}
```

**Denetim izi middleware:**

```javascript
async function createAuditLog({ userId, userEmail, action, resource, resourceId, oldValue, newValue, ipAddress, userAgent, details }) {
  try {
    await prisma.auditLog.create({
      data: {
        userId,
        userEmail,
        action,
        resource,
        resourceId: String(resourceId || ''),
        oldValue: oldValue ? JSON.stringify(oldValue) : null,
        newValue: newValue ? JSON.stringify(newValue) : null,
        ipAddress,
        userAgent,
        details
      }
    });
  } catch (err) {
    logger.error('Audit log oluşturma hatası:', err);
  }
}

// Kullanım örnekleri:

// Login başarılı
await createAuditLog({
  userId: user.id,
  userEmail: user.email,
  action: 'LOGIN',
  resource: 'User',
  resourceId: user.id,
  ipAddress: req.ip,
  userAgent: req.get('User-Agent')
});

// Login başarısız
await createAuditLog({
  action: 'LOGIN_FAILED',
  resource: 'User',
  details: `Başarısız giriş: ${email}`,
  ipAddress: req.ip,
  userAgent: req.get('User-Agent')
});

// Kullanıcı silme
await createAuditLog({
  userId: req.user.id,
  userEmail: req.user.email,
  action: 'DELETE',
  resource: 'User',
  resourceId: id,
  oldValue: deletedUser,
  ipAddress: req.ip,
  userAgent: req.get('User-Agent')
});

// Denetim onay/red
await createAuditLog({
  userId: req.user.id,
  userEmail: req.user.email,
  action: 'UPDATE',
  resource: 'Audit',
  resourceId: auditId,
  oldValue: { status: audit.status },
  newValue: { status: newStatus, reviewerId: req.user.id },
  ipAddress: req.ip,
  userAgent: req.get('User-Agent'),
  details: action === 'approve' ? 'Denetim onaylandı' : `Revizyon talep edildi: ${note}`
});
```

### 5.3 Loglanması Gereken Olaylar

| Kategori | Olaylar | Seviye |
|----------|---------|--------|
| **Kimlik Doğrulama** | Başarılı/başarısız giriş, çıkış, token yenileme, hesap kilitleme | warn/info |
| **Yetki** | Erişim reddi (403), rol değişikliği, yetki yükseltme | warn |
| **Veri İşlemleri** | Kullanıcı CRUD, şirket/şube CRUD, denetim oluşturma/onay/red/silme | info |
| **Konfigürasyon** | Şifre değişikliği, profil güncelleme, sistem ayarı değişikliği | info |
| **Dosya İşlemleri** | Dosya yükleme, dosya erişimi, dosya silme | info |
| **Güvenlik Olayları** | Rate limit aşımı, CSRF token hatası, geçersiz token | warn |

### 5.4 Log'larda PII Sızıntı Önleme

**Yapılacaklar:**

- [ ] Log'lara şifre, token veya kredi kartı bilgisi yazılmamasını garanti et
- [ ] E-posta adreslerini log'larda maskele (isteğe bağlı)

```javascript
function sanitizeLogData(data) {
  if (!data || typeof data !== 'object') return data;

  const sensitiveKeys = ['password', 'token', 'secret', 'authorization', 'cookie', 'creditCard'];
  const sanitized = { ...data };

  for (const key of Object.keys(sanitized)) {
    if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
      sanitized[key] = '[REDACTED]';
    }
  }

  return sanitized;
}
```

### 5.5 Log Bütünlüğü

**Yapılacaklar:**

- [ ] Log dosyaları salt-okunur (append-only) modda yazılsın
- [ ] Günlük log dosyası hash'i alınsın
- [ ] Log dosyalarının izinsiz değiştirilmesi tespit edilebilsin

```javascript
const crypto = require('crypto');

function hashLogFile(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

// Günlük log rotasyonu sonrası hash oluştur
// logs/checksums.json dosyasında sakla
function logFileIntegrityCheck(filename) {
  const hash = hashLogFile(`logs/${filename}`);
  const checksumFile = 'logs/checksums.json';
  let checksums = {};

  if (fs.existsSync(checksumFile)) {
    checksums = JSON.parse(fs.readFileSync(checksumFile, 'utf-8'));
  }

  checksums[filename] = {
    hash,
    timestamp: new Date().toISOString()
  };

  fs.writeFileSync(checksumFile, JSON.stringify(checksums, null, 2));
}
```

### 5.6 Log Saklama Politikası

| Log Tipi | Saklama Süresi | Depolama |
|----------|---------------|----------|
| Güvenlik logları (auth, erişim reddi) | 12 ay (minimum) | Hot storage (3 ay) + Archive (9 ay) |
| Denetim izi (audit trail) | 36 ay | Veritabanı + yedek |
| HTTP erişim logları | 12 ay | Dosya sistemi (sıkıştırılmış) |
| Uygulama hata logları | 12 ay | Dosya sistemi (sıkıştırılmış) |
| Debug logları | 30 gün | Dosya sistemi |

### Faz 5 Kontrol Listesi

- [ ] Winston/Pino kuruldu ve yapılandırıldı
- [ ] Morgan kaldırıldı, yapılandırılmış JSON loglama aktif
- [ ] AuditLog modeli Prisma schema'ya eklendi
- [ ] Tüm kritik işlemler için denetim izi oluşturuluyor
- [ ] Başarısız giriş denemeleri loglanıyor
- [ ] Yetki değişiklikleri loglanıyor
- [ ] CRUD işlemleri loglanıyor (eski/yeni değer dahil)
- [ ] Log'larda PII sızıntı önleme aktif
- [ ] Log dosyası bütünlük kontrolü (hash) uygulandı
- [ ] Log saklama politikası belgelendi ve uygulandı (min 12 ay)
- [ ] Log rotasyonu yapılandırıldı (günlük dosya, sıkıştırma)

---

## Faz 6 — CI/CD ve Güvenlik Test Altyapısı

> **ISO Referansları:** Ek A 8.29 (Güvenlik Testi), Ek A 8.8 (Teknik Zafiyetlerin Yönetimi), Ek A 8.25 (Güvenli SDLC)  
> **Öncelik:** Orta  
> **Tahmini Süre:** 7-10 gün

### 6.1 GitHub Actions CI/CD Pipeline

**Yapılacaklar:**

- [ ] `.github/workflows/security.yml` oluştur
- [ ] Her PR ve push'ta otomatik güvenlik taraması çalıştır

```yaml
# .github/workflows/security.yml
name: Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  # 1. Bağımlılık güvenlik taraması (SCA)
  dependency-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Node.js kurulumu
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Backend bağımlılık taraması
        working-directory: teftispro/backend
        run: |
          npm ci
          npm audit --audit-level=high

      - name: Frontend bağımlılık taraması
        working-directory: teftispro/frontend
        run: |
          npm ci
          npm audit --audit-level=high

  # 2. Statik kod analizi (SAST)
  sast:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: CodeQL analizi
        uses: github/codeql-action/init@v3
        with:
          languages: javascript

      - name: CodeQL taraması
        uses: github/codeql-action/analyze@v3

  # 3. Secret taraması
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Gitleaks secret taraması
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  # 4. Linting ve kod kalitesi
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Node.js kurulumu
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: ESLint güvenlik kuralları
        working-directory: teftispro/backend
        run: |
          npm ci
          npx eslint --ext .js src/ --rule '{"no-eval": "error", "no-implied-eval": "error"}'
```

### 6.2 SAST Araç Entegrasyonu (Semgrep)

**Yapılacaklar:**

- [ ] Semgrep yapılandırması oluştur
- [ ] Node.js ve Express güvenlik kurallarını aktif et

```yaml
# .semgrep.yml
rules:
  - id: hardcoded-secret
    pattern: |
      const $VAR = "..."
    message: Hardcoded secret tespit edildi
    severity: ERROR
    languages: [javascript]

  - id: sql-injection
    pattern: |
      prisma.$queryRawUnsafe(...)
    message: Güvensiz raw SQL sorgusu
    severity: ERROR
    languages: [javascript]
```

### 6.3 SCA — Bağımlılık Taraması

**Yapılacaklar:**

- [ ] GitHub Dependabot'u aktif et
- [ ] `npm audit` CI pipeline'a entegre et
- [ ] Kritik CVE'lerde build'i durdur

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/teftispro/backend"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"

  - package-ecosystem: "npm"
    directory: "/teftispro/frontend"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
```

### 6.4 SBOM (Yazılım Malzeme Listesi)

**Yapılacaklar:**

- [ ] CycloneDX formatında SBOM oluştur
- [ ] Her release'de SBOM'u güncelle

```bash
# Backend SBOM oluşturma
cd teftispro/backend
npx @cyclonedx/cyclonedx-npm --output-file sbom.json

# Frontend SBOM oluşturma
cd teftispro/frontend
npx @cyclonedx/cyclonedx-npm --output-file sbom.json
```

### 6.5 Pre-commit Hook'ları

**Yapılacaklar:**

- [ ] `husky` ve `lint-staged` kur
- [ ] Secret detection hook ekle
- [ ] Commit öncesi güvenlik kontrolü

```bash
npm install -D husky lint-staged
npx husky init
```

```json
// package.json
{
  "lint-staged": {
    "*.js": [
      "eslint --fix",
      "git add"
    ]
  }
}
```

```bash
# .husky/pre-commit
#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

# Secret taraması
npx gitleaks detect --source . --no-git --verbose

# Lint
npx lint-staged
```

### 6.6 Penetrasyon Testi Planı

| Test Türü | Sıklık | Kapsam | Sorumlu |
|-----------|--------|--------|---------|
| Otomatik zafiyet taraması (DAST) | Her sprint | Tüm API endpoint'leri | DevSecOps |
| Manuel sızma testi | Yılda 1 kez | Tam kapsam (web + API + altyapı) | Harici güvenlik firması |
| Hedefli sızma testi | Büyük release sonrası | Yeni özellikler ve değişen API'ler | İç güvenlik ekibi |
| Red team egzersizi | Yılda 1 kez | Sosyal mühendislik dahil tam kapsam | Harici firma |

**DAST aracı entegrasyonu (OWASP ZAP):**

```yaml
# .github/workflows/dast.yml (ayrı workflow)
name: DAST Scan

on:
  schedule:
    - cron: '0 2 * * 1' # Her Pazartesi 02:00

jobs:
  zap-scan:
    runs-on: ubuntu-latest
    steps:
      - name: OWASP ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.10.0
        with:
          target: ${{ secrets.STAGING_URL }}
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
```

### 6.7 Ortam Ayrımı (Ek A 8.31)

**Yapılacaklar:**

- [ ] Development, staging ve production ortamlarını ayrı yapılandır
- [ ] Her ortam için ayrı veritabanı ve secret'lar
- [ ] Production verileri asla dev/test ortamına aktarılmamalı

| Ortam | Amaç | Veritabanı | Erişim |
|-------|-------|-----------|--------|
| Development | Geliştirme | SQLite (local) | Tüm geliştiriciler |
| Staging | Test ve QA | PostgreSQL (izole) | QA ekibi + seçili geliştiriciler |
| Production | Canlı | PostgreSQL (şifreli) | Sadece CI/CD + ops ekibi |

### Faz 6 Kontrol Listesi

- [ ] GitHub Actions CI/CD pipeline oluşturuldu
- [ ] SAST (CodeQL/Semgrep) entegre edildi
- [ ] SCA (npm audit + Dependabot) aktif
- [ ] Secret taraması (Gitleaks) CI'a eklendi
- [ ] SBOM oluşturuldu (CycloneDX)
- [ ] Pre-commit hook'ları kuruldu (husky)
- [ ] DAST (OWASP ZAP) yapılandırıldı
- [ ] Penetrasyon testi takvimi belirlendi
- [ ] Ortam ayrımı (dev/staging/production) belgelendi

---

## Faz 7 — Bulut, Altyapı ve Dağıtım Güvenliği

> **ISO Referansları:** Ek A 5.23 (Bulut Hizmetleri Güvenliği), Ek A 8.9 (Yapılandırma Yönetimi)  
> **Öncelik:** Orta  
> **Tahmini Süre:** 10-14 gün

### 7.1 Docker Containerization

**Yapılacaklar:**

- [ ] Backend Dockerfile oluştur
- [ ] Frontend Dockerfile oluştur
- [ ] docker-compose.yml oluştur
- [ ] Non-root kullanıcı ile çalıştır

**Backend Dockerfile:**

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY prisma ./prisma
RUN npx prisma generate

FROM node:20-alpine
RUN addgroup -g 1001 appgroup && adduser -u 1001 -G appgroup -s /bin/sh -D appuser
WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/prisma ./prisma
COPY src ./src

RUN mkdir -p uploads logs && chown -R appuser:appgroup /app
USER appuser

EXPOSE 3636
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3636/health || exit 1

CMD ["node", "src/server.js"]
```

**docker-compose.yml:**

```yaml
version: '3.8'

services:
  backend:
    build:
      context: ./teftispro/backend
    ports:
      - "3636:3636"
    environment:
      - NODE_ENV=production
      - JWT_SECRET=${JWT_SECRET}
      - DATABASE_URL=postgresql://teftispro:${DB_PASSWORD}@db:5432/teftispro
      - ALLOWED_ORIGINS=https://yourdomain.com
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - uploads:/app/uploads
      - logs:/app/logs
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'

  frontend:
    build:
      context: ./teftispro/frontend
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - backend
    restart: unless-stopped

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=teftispro
      - POSTGRES_USER=teftispro
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U teftispro"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

volumes:
  pgdata:
  uploads:
  logs:
```

### 7.2 SQLite'dan PostgreSQL'e Geçiş

**Sorun:** SQLite production ortamı için uygun değil (eşzamanlı yazma kısıtı, şifreleme desteği yok).

**Yapılacaklar:**

- [ ] PostgreSQL Prisma provider'ını yapılandır
- [ ] Migration planı oluştur
- [ ] Veri taşıma script'i hazırla
- [ ] Connection pooling ayarla

```prisma
// schema.prisma — Production için
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}
```

```
# .env (PostgreSQL)
DATABASE_URL="postgresql://teftispro:STRONG_PASSWORD@localhost:5432/teftispro?schema=public&connection_limit=20"
```

### 7.3 Health Check Endpoint

**Yapılacaklar:**

- [ ] `/health` endpoint'i ekle (container orchestration ve monitoring için)

```javascript
app.get('/health', async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      database: 'connected'
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      database: 'disconnected'
    });
  }
});
```

### 7.4 Veri Lokasyonu ve KVKK Uyumu

**Yapılacaklar:**

- [ ] Verilerin Türkiye sınırları içinde saklandığını garanti et
- [ ] Bulut sağlayıcı seçiminde TR region zorunluluğu
- [ ] Veri işleme envanteri ve KVKK uyum belgesi hazırla
- [ ] Kişisel veri silme (unutulma hakkı) endpoint'i oluştur

### 7.5 Tedarikçi Güvenlik Değerlendirmesi

**Kullanılan üçüncü taraf hizmetler ve değerlendirme:**

| Hizmet/Paket | Amaç | Risk | Güvenlik Notu |
|-------------|------|------|--------------|
| npm paketleri (express, prisma vb.) | Backend framework | Orta | Dependabot + npm audit ile izle |
| Tailwind CDN | CSS framework | Yüksek | Lokal build'e geçilmeli (Faz 3) |
| Google Fonts CDN | Font | Düşük | SRI hash ekle |
| Bulut sağlayıcı | Barındırma | Yüksek | ISO 27001 sertifikalı sağlayıcı seç |

### 7.6 Çıkış Stratejisi (Exit Strategy)

**Yapılacaklar:**

- [ ] Bulut sağlayıcıdan bağımsız IaC şablonları (Terraform)
- [ ] Veritabanı dışa aktarma prosedürü belgelenmeli
- [ ] Yedekleme dosyaları sağlayıcıdan bağımsız formatta tutulmalı
- [ ] Tahmini taşınma süresi ve RTO belgelenmeli

### Faz 7 Kontrol Listesi

- [ ] Backend ve Frontend Dockerfile oluşturuldu
- [ ] docker-compose.yml hazırlandı
- [ ] Non-root container kullanıcısı ayarlandı
- [ ] SQLite'dan PostgreSQL'e geçiş planı hazır
- [ ] Health check endpoint eklendi
- [ ] KVKK uyum belgesi hazırlandı
- [ ] Tedarikçi güvenlik değerlendirmesi yapıldı
- [ ] Çıkış stratejisi belgelendi
- [ ] IaC şablonları oluşturuldu

---

## Faz 8 — İş Sürekliliği ve Felaket Kurtarma

> **ISO Referansları:** Ek A 5.30 (BİT İş Sürekliliği), Ek A 8.13 (Bilgi Yedekleme), Ek A 8.14 (Bilgi İşleme Tesisleri Yedekliliği)  
> **Öncelik:** Planlanan  
> **Tahmini Süre:** 5-7 gün

### 8.1 İş Etki Analizi (BIA)

| Uygulama Bileşeni | Önem Derecesi | RTO | RPO |
|-------------------|--------------|-----|-----|
| Web API (backend) | Tier 2 — İş İçin Gerekli | 1 saat | 1 saat |
| Veritabanı (PostgreSQL) | Tier 1 — Kritik | 30 dakika | 15 dakika |
| Frontend (statik dosyalar) | Tier 3 — Önemli | 2 saat | 24 saat |
| Dosya depolama (uploads) | Tier 2 — İş İçin Gerekli | 2 saat | 4 saat |
| Log sistemi | Tier 3 — Önemli | 4 saat | 1 saat |

### 8.2 Veritabanı Yedekleme Stratejisi

**Yapılacaklar:**

- [ ] Otomatik günlük tam yedekleme (full backup)
- [ ] Saatlik artımlı yedekleme (incremental)
- [ ] Yedeklerin AES-256 ile şifrelenmesi
- [ ] Yedeklerin farklı coğrafi konumda saklanması

```bash
#!/bin/bash
# scripts/backup.sh — Günlük veritabanı yedeği

BACKUP_DIR="/backups/postgresql"
DATE=$(date +%Y%m%d_%H%M%S)
FILENAME="teftispro_${DATE}.sql.gz"

# Dump al ve sıkıştır
pg_dump -h localhost -U teftispro teftispro | gzip > "${BACKUP_DIR}/${FILENAME}"

# AES-256 ile şifrele
openssl enc -aes-256-cbc -salt \
  -in "${BACKUP_DIR}/${FILENAME}" \
  -out "${BACKUP_DIR}/${FILENAME}.enc" \
  -pass file:/etc/backup/encryption.key

# Şifrelenmemiş dosyayı sil
rm "${BACKUP_DIR}/${FILENAME}"

# SHA-256 hash oluştur (bütünlük kontrolü için)
sha256sum "${BACKUP_DIR}/${FILENAME}.enc" >> "${BACKUP_DIR}/checksums.sha256"

# 90 günden eski yedekleri temizle (lokal)
find "${BACKUP_DIR}" -name "*.enc" -mtime +90 -delete

# Uzak depolamaya kopyala (S3 veya benzeri)
# aws s3 cp "${BACKUP_DIR}/${FILENAME}.enc" s3://teftispro-backups/daily/
```

**Cron yapılandırması:**

```cron
# Günlük tam yedekleme — 02:00
0 2 * * * /opt/teftispro/scripts/backup.sh >> /var/log/backup.log 2>&1

# Saatlik artımlı yedekleme (WAL archiving ile)
0 * * * * /opt/teftispro/scripts/incremental-backup.sh >> /var/log/backup.log 2>&1
```

### 8.3 Yedek Bütünlük Testi

**Yapılacaklar:**

- [ ] Aylık yedek geri yükleme testi
- [ ] Test sonuçlarını belgele
- [ ] Otomatik bütünlük doğrulama script'i

```bash
#!/bin/bash
# scripts/verify-backup.sh — Yedek bütünlük doğrulama

LATEST_BACKUP=$(ls -t /backups/postgresql/*.enc | head -1)

# Hash kontrolü
sha256sum -c /backups/postgresql/checksums.sha256 --quiet

# Test geri yükleme (izole ortamda)
openssl enc -aes-256-cbc -d \
  -in "${LATEST_BACKUP}" \
  -out /tmp/test_restore.sql.gz \
  -pass file:/etc/backup/encryption.key

gunzip -t /tmp/test_restore.sql.gz
if [ $? -eq 0 ]; then
  echo "[$(date)] Yedek bütünlük testi BAŞARILI: ${LATEST_BACKUP}"
else
  echo "[$(date)] UYARI: Yedek bütünlük testi BAŞARISIZ: ${LATEST_BACKUP}"
  # Alarm gönder
fi

rm -f /tmp/test_restore.sql.gz
```

### 8.4 Felaket Kurtarma Senaryoları

| Senaryo | Eylem Planı | RTO |
|---------|-------------|-----|
| Veritabanı bozulması | En son yedekten geri yükle, WAL replay | 30 dk |
| Sunucu çökmesi | Yedek sunucuya failover, DNS güncelleme | 1 saat |
| Ransomware saldırısı | Air-gapped yedekten geri yükle, temiz ortam kur | 4 saat |
| Bulut sağlayıcı kesintisi | Alternatif sağlayıcıya geçiş (çıkış stratejisi) | 8 saat |
| Veri merkezinde fiziksel hasar | Coğrafi yedek konumdan geri yükle | 24 saat |

### 8.5 Olay Müdahale (Incident Response) Prosedürü

**Olay müdahale aşamaları:**

1. **Tespit (Detection):** SIEM alarmları, kullanıcı bildirimleri, otomatik izleme
2. **Sınıflandırma (Triage):** Olayın ciddiyetini belirle (P1-P4)
3. **Kontrol Altına Alma (Containment):** Etkilenen sistemi izole et
4. **İyileştirme (Eradication):** Temel nedeni tespit et ve düzelt
5. **Kurtarma (Recovery):** Sistemi güvenli duruma geri getir
6. **Sonuç Analizi (Lessons Learned):** Olay sonrası rapor ve iyileştirme

**Olay ciddiyet seviyeleri:**

| Seviye | Tanım | Yanıt Süresi | Örnek |
|--------|-------|-------------|-------|
| P1 — Kritik | Veri ihlali veya sistem tamamen çöktü | 15 dakika | Veritabanı sızıntısı, ransomware |
| P2 — Yüksek | Kısmi hizmet kesintisi veya güvenlik açığı tespit edildi | 1 saat | API çökmesi, brute-force saldırısı |
| P3 — Orta | Performans düşüklüğü veya minör güvenlik olayı | 4 saat | Rate limit aşımı, şüpheli giriş |
| P4 — Düşük | Bilgi amaçlı olay | 24 saat | Port taraması, otomatik bot trafiği |

### 8.6 Tatbikat Takvimi

| Tatbikat | Sıklık | Kapsam |
|----------|--------|--------|
| Yedek geri yükleme testi | Aylık | Veritabanı + dosya yedekleri |
| Failover testi | 6 ayda bir | Sunucu ve veritabanı failover |
| Tam felaket kurtarma tatbikatı | Yılda 1 kez | Tüm sistemlerin sıfırdan kurtarılması |
| Masa başı olay müdahale egzersizi | 6 ayda bir | Ekip koordinasyonu ve iletişim |

### Faz 8 Kontrol Listesi

- [ ] İş Etki Analizi (BIA) tamamlandı
- [ ] RTO/RPO metrikleri belirlendi
- [ ] Otomatik günlük veritabanı yedeği yapılandırıldı
- [ ] Yedekler AES-256 ile şifreleniyor
- [ ] Yedek bütünlük testi script'i oluşturuldu
- [ ] Aylık geri yükleme testi takvimi belirlendi
- [ ] Felaket kurtarma senaryoları belgelendi
- [ ] Olay müdahale prosedürü oluşturuldu
- [ ] Ciddiyet seviyeleri ve yanıt süreleri tanımlandı
- [ ] Tatbikat takvimi oluşturuldu

---

## Uygulama Öncelik Sıralaması

```
Faz 1 (Acil)        ████████████ 3-5 gün    — Kritik açıkların kapatılması
Faz 2 (Yüksek)      ████████████████ 5-7 gün — Kimlik doğrulama güçlendirme
Faz 3 (Yüksek)      ████████████████ 5-7 gün — Frontend güvenliği
Faz 4 (Orta-Yüksek) ████████████████████ 7-10 gün — Backend + kriptografi
Faz 5 (Orta)        ████████████████████ 7-10 gün — Loglama + izleme
Faz 6 (Orta)        ████████████████████ 7-10 gün — CI/CD + güvenlik testleri
Faz 7 (Orta)        ████████████████████████ 10-14 gün — Altyapı + bulut
Faz 8 (Planlanan)   ████████████████ 5-7 gün — İş sürekliliği
```

**Toplam Tahmini Süre:** 50-70 gün (paralel çalışmalarla 35-45 güne düşürülebilir)

---

## Yeni Paketler (Kurulacak)

### Backend

```bash
cd teftispro/backend
npm install dotenv cookie-parser winston winston-daily-rotate-file express-winston
npm install -D eslint husky lint-staged @cyclonedx/cyclonedx-npm
```

### Frontend

```bash
cd teftispro/frontend
npm install -D tailwindcss
```

---

## ISO 27001:2022 Kontrol Eşleştirme Tablosu

| Ek A Kontrol | Açıklama | İlgili Faz |
|-------------|----------|-----------|
| 5.7 | Tehdit İstihbaratı | Faz 6, 8 |
| 5.17 | Kimlik Doğrulama Bilgileri | Faz 2 |
| 5.23 | Bulut Hizmetleri Güvenliği | Faz 7 |
| 5.30 | BİT İş Sürekliliği | Faz 8 |
| 7.4 | Fiziksel Güvenlik İzleme | Faz 7 (altyapı) |
| 8.5 | Güvenli Kimlik Doğrulama | Faz 2 |
| 8.8 | Teknik Zafiyetlerin Yönetimi | Faz 6 |
| 8.9 | Yapılandırma Yönetimi | Faz 1, 7 |
| 8.10 | Bilgi Silme | Faz 7 (KVKK) |
| 8.11 | Veri Maskeleme | Faz 4 |
| 8.12 | Veri Sızıntısını Önleme | Faz 3, 5 |
| 8.13 | Bilgi Yedekleme | Faz 8 |
| 8.15 | Loglama | Faz 5 |
| 8.16 | İzleme Faaliyetleri | Faz 5 |
| 8.23 | Web Filtreleme | Faz 1 (CSP) |
| 8.24 | Kriptografi Kullanımı | Faz 1, 2, 4 |
| 8.25 | Güvenli SDLC | Faz 6 |
| 8.26 | Uygulama Güvenliği Gereksinimleri | Tüm Fazlar |
| 8.28 | Güvenli Kodlama | Faz 1, 3, 4 |
| 8.29 | Güvenlik Testi | Faz 6 |
| 8.31 | Ortam Ayrımı | Faz 6, 7 |
| 8.32 | Değişiklik Yönetimi | Faz 6 (CI/CD) |

---

> **Not:** Bu doküman yaşayan bir belgedir. Her faz tamamlandıkça kontrol listesi işaretlenmeli, yapılan değişiklikler ve tarihler güncellenmeli, ISO 27001 iç denetim süreçlerinde bu doküman referans alınmalıdır.
