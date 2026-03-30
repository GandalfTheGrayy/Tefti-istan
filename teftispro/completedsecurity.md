# TeftişPro — Güvenlik Uygulaması Tamamlandı (Faz 1 + Faz 2 + Faz 3 + Faz 4 + Faz 5)

> **Proje:** TeftişPro - Teftiş ve Kalite Kontrol Uygulaması  
> **Faz 1:** Kritik Güvenlik Açıklarının Kapatılması  
> **Faz 2:** Kimlik Doğrulama ve Oturum Güvenliği  
> **Faz 3:** Frontend Güvenliği (XSS, CSRF, CSP)  
> **Faz 4:** Backend Güvenliği ve Kriptografik Kontroller  
> **Faz 5:** Loglama, İzleme ve Denetim İzleri  
> **ISO Referansları:** Ek A 5.17, Ek A 8.5, Ek A 8.11, Ek A 8.15, Ek A 8.16, Ek A 8.24, Ek A 8.28, Ek A 8.12  
> **Tamamlanma Tarihi:** 2026-03-05

---

## Özet

- **Faz 1:** 9 ana madde uygulandı. Tüm kritik güvenlik açıkları kapatıldı.
- **Faz 2:** 6 ana madde uygulandı. JWT HttpOnly cookie, refresh token, şifre politikası, hesap kilitleme, logout endpoint, login rate limit sıkılaştırıldı.
- **Faz 3:** 5 ana madde uygulandı. DOMPurify XSS koruması, innerHTML safeText, CSRF token, Tailwind lokal build, CSP güncellemesi.
- **Faz 4:** 7 ana madde uygulandı. Zod validasyon, Prisma password maskeleme, x-powered-by kaldırma, Prisma hata kodları, rate limit genişletme, modüler schemas/middleware, TLS dokümantasyonu.
- **Faz 5:** 6 ana madde uygulandı. Winston JSON loglama, AuditLog denetim izi, PII sanitizeLogData, Morgan kaldırıldı, tüm kritik endpoint'lere audit log.

---

## 1.1 Ortam Değişkenleri ve Sır Yönetimi

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/`

| İşlem | Detay |
|-------|-------|
| dotenv kurulumu | `npm install dotenv` |
| .env.example | Şablon oluşturuldu (gerçek değerler olmadan) |
| .env | Geliştirme için JWT_SECRET ile oluşturuldu |
| server.js | `require('dotenv').config()` en üste eklendi |
| server.js | JWT_SECRET fallback kaldırıldı, zorunlu hale getirildi |

**Önceki kod (server.js):**
```javascript
const JWT_SECRET = process.env.JWT_SECRET || 'teftispro-super-secret-key-2024';
```

**Sonraki kod:**
```javascript
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET ortam değişkeni tanımlı değil. Uygulama başlatılamıyor.');
  process.exit(1);
}
```

**Test:** T1, T2

---

## 1.2 CORS Yapılandırması

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

**Önceki kod:**
```javascript
app.use(cors({ origin: true, credentials: true }));
```

**Sonraki kod:**
```javascript
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean);

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
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600
}));
```

**Test:** T3, T4

---

## 1.3 Body Limit Düşürme

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

**Önceki kod:**
```javascript
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
```

**Sonraki kod:**
```javascript
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
```

**Not:** Fotoğraflar Multer (FormData) ile yüklenir; JSON limiti sadece API payload'larını etkiler. İmza endpoint'i base64 JSON kullandığı için 2MB yeterli.

**Test:** T5

---

## 1.4 Global Error Handler

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

- 404 handler eklendi
- Global error handler (ZodError, CORS, production stack trace gizleme)
- `uncaughtException` ve `unhandledRejection` işleyicileri

**Eklenen kod:**
```javascript
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
  const isProduction = process.env.NODE_ENV === 'production';
  console.error('Unhandled error:', err);
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
```

**Test:** T6

---

## 1.5 Dosya Yükleme Güvenliği

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

- `ALLOWED_IMAGE_MIME` ve `ALLOWED_IMAGE_EXT` whitelist
- `ALLOWED_WITH_PDF_MIME` ve `ALLOWED_WITH_PDF_EXT` (genel upload için)
- Multer `fileFilter` (MIME + uzantı kontrolü)
- Path traversal koruması (`..`, `\0` kontrolü)
- Dosya boyutu 10MB → 5MB
- İki Multer instance: `uploadImagesOnly` (foto/imza), `uploadWithPdf` (genel)

**Test:** T7

---

## 1.5b Fotoğraf Sıkıştırma

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

- `sharp` paketi kuruldu
- `compressImage()` helper: max 1920px, JPEG %80 kalite veya PNG optimize
- Uygulanan endpoint'ler:
  - `POST /audits/:id/photos` — JPEG sıkıştırma
  - `POST /audits/:id/signatures` — PNG optimize (imza okunabilirliği)
  - `POST /upload` — Resimler için JPEG sıkıştırma

**Test:** T8, T12

---

## 1.5c Zararlı Dosya Yükleme Koruması

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

- **Magic bytes doğrulama:** Dosya içeriğinin ilk 12 byte'ı ile format kontrolü (JPEG, PNG, GIF, WebP, PDF)
- **SVG hariç:** Whitelist'e eklenmedi (JavaScript/XXE riski)
- **Sharp re-encode:** Sıkıştırma sırasında decode→re-encode ile polyglot içerik temizlenir
- **PDF ayrımı:** Fotoğraf endpoint'lerinde sadece resim; PDF sadece `/upload`'da

**Test:** T13

---

## 1.6 Helmet ve CSP Yapılandırması

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

**Önceki kod:**
```javascript
app.use(helmet({ crossOriginResourcePolicy: false }));
```

**Sonraki kod:**
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
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));
```

---

## 1.7 HTTPS Yönlendirmesi (Production)

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

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

---

## 1.8 Upload Dizini Erişim Kontrolü

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

**Önceki kod:**
```javascript
app.use('/uploads', express.static(uploadsDir));
```

**Sonraki kod:** `/uploads` route'u `authenticate` middleware'inden sonra taşındı:
```javascript
app.use('/uploads', authenticate, express.static(uploadsDir));
```

**Test:** T9, T10

---

## 1.9 Demo Hesap Bilgilerinin Production'da Gizlenmesi

### Yapılan Değişiklikler

**Dosya:** `teftispro/frontend/public/login.html`

- Demo hesaplar bölümüne `id="demoAccountsSection"` eklendi
- `DOMContentLoaded` içinde hostname kontrolü: `localhost` veya `127.0.0.1` değilse bölüm gizlenir

```javascript
if (demoSection && !['localhost', '127.0.0.1'].includes(window.location.hostname)) {
  demoSection.style.display = 'none';
}
```

**Test:** T11

---

## Test Sonuçları

| Test | Adım | Beklenen | Sonuç |
|------|------|----------|-------|
| T1 | JWT_SECRET olmadan başlat | Uygulama başlamaz, exit 1 | Geçti |
| T2 | .env ile geçerli JWT_SECRET ile başlat | Sunucu ayağa kalkar | Geçti |
| T3 | İzin verilmeyen origin'den istek | 403 CORS hatası | Geçti |
| T4 | localhost:2525'ten login | CORS geçer, login başarılı | Geçti |
| T5 | 2MB+ JSON body gönder | 413 veya payload too large | Geçti (413) |
| T6 | 404 route | `{"error":"İstenen kaynak bulunamadı"}` | Geçti |
| T7 | Geçersiz dosya tipi yükle | "Desteklenmeyen dosya formatı" | Geçti |
| T8 | Geçerli JPG yükle | 201, fotoğraf kaydedilir (sıkıştırılmış) | Geçti |
| T9 | Token olmadan /uploads/xxx | 401 | Geçti |
| T10 | Token ile /uploads/xxx | 200, dosya döner | Geçti |
| T11 | Production'da demo butonları | Gizli (hostname != localhost) | Geçti (kod ile) |
| T12 | Büyük JPG yükle (örn. 4MB) | 201, sıkıştırılmış kaydedilir | Geçti |
| T13 | MIME spoofing (Content-Type: image/jpeg, içerik PHP) | 400, magic bytes uyumsuz | Geçti |

---

## Dosya Değişiklik Listesi

| Dosya | İşlem |
|-------|-------|
| `teftispro/backend/package.json` | dotenv, sharp dependency eklendi |
| `teftispro/backend/.env.example` | Yeni oluşturuldu |
| `teftispro/backend/.env` | Yeni oluşturuldu (dev için) |
| `teftispro/backend/src/server.js` | 1.1–1.8, 1.5b, 1.5c tüm değişiklikler |
| `teftispro/frontend/public/login.html` | Demo bölümü hostname ile gizleme |
| `teftispro/completedsecurity.md` | Bu dokümantasyon |

---

## Kurulum Notları

1. Backend dizininde `npm install` çalıştırın (dotenv, sharp kurulacak)
2. `.env.example`'ı `.env` olarak kopyalayın ve `JWT_SECRET` değerini doldurun
3. JWT_SECRET üretmek için: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`
4. `.env` içinde `ALLOWED_ORIGINS` frontend URL'ini içermeli (örn. `http://localhost:2525`)

---

# Faz 2 — Kimlik Doğrulama ve Oturum Güvenliği

> **ISO Referansları:** Ek A 5.17 (Kimlik Doğrulama Bilgileri), Ek A 8.5 (Güvenli Kimlik Doğrulama), Ek A 8.24 (Kriptografi Kullanımı)

---

## 2.1 JWT Token'ı HttpOnly Cookie'ye Taşıma

### Yapılan Değişiklikler

**Backend — `teftispro/backend/src/server.js`**

| İşlem | Detay |
|-------|-------|
| cookie-parser | `app.use(cookieParser())` eklendi |
| Login response | Token JSON yerine `Set-Cookie` ile gönderiliyor |
| access_token | path `/`, httpOnly, secure (production), sameSite: strict, 1 saat |
| refresh_token | path `/auth/refresh`, 7 gün |
| authenticate | Önce `req.cookies?.access_token`, yoksa `Authorization` header |
| TokenExpiredError | `code: 'TOKEN_EXPIRED'` döndürülüyor (frontend refresh için) |

**Frontend — `teftispro/frontend/public/layout.js`**

- `apiFetch` helper: `credentials: 'include'`, 401'de refresh dene, TOKEN_EXPIRED ise `/auth/refresh` çağır
- `logout()`: `POST /auth/logout` credentials ile çağır, cookie temizle

**Frontend — Tüm sayfalar**

- `localStorage.setItem('token', ...)` kaldırıldı
- `Authorization: Bearer ${token}` header kaldırıldı
- `apiFetch` veya `credentials: 'include'` kullanılıyor
- Auth kontrolü: `LAYOUT.getUser()` veya `localStorage.getItem('user')`

**Test:** T2.1, T2.2, T2.3, T2.4, T2.11

---

## 2.2 Şifre Karmaşıklık Politikası

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

- `passwordSchema` (Zod): min 12 karakter, büyük harf, küçük harf, rakam, özel karakter
- `BCRYPT_ROUNDS = 12`
- `POST /users`: passwordSchema, bcrypt 12
- `PUT /profile/password`: newPassword için passwordSchema, bcrypt 12

**Frontend:** `profil.html` minlength 12, şifre kuralları metni; `admin_yonetimi.html` yeni kullanıcı şifresi minlength 12

**Test:** T2.5, T2.6

---

## 2.3 Hesap Kilitleme Mekanizması

### Yapılan Değişiklikler

**Prisma schema:** `failedLoginAttempts`, `lockedUntil` (migration mevcut)

**Login endpoint:**
- `lockedUntil > new Date()` ise 423 + "Hesap kilitli. X dakika sonra tekrar deneyin."
- Şifre hatalı: `failedLoginAttempts++`, 5'e ulaşınca `lockedUntil = now + 15dk`
- Başarılı giriş: `failedLoginAttempts = 0`, `lockedUntil = null`

**Test:** T2.7, T2.8

---

## 2.4 Token Süresi ve Refresh Token

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

- `generateToken`: `expiresIn: JWT_EXPIRES_IN || '1h'`
- `generateRefreshToken`: `{ id, type: 'refresh' }`, 7 gün
- `POST /auth/refresh`: refresh_token cookie'den oku, verify, yeni access_token set et

**Test:** T2.9

---

## 2.5 Logout Endpoint

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

```javascript
app.post('/auth/logout', (req, res) => {
  res.clearCookie('access_token', { path: '/' });
  res.clearCookie('refresh_token', { path: '/auth/refresh' });
  res.json({ message: 'Çıkış yapıldı' });
});
```

**Frontend:** `layout.js` — `logout()` artık `POST /auth/logout` credentials ile çağırıyor

**Test:** T2.4

---

## 2.6 Login Rate Limit Sıkılaştırma

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

- windowMs: 15 dakika
- max: 5 (LOGIN_RATE_LIMIT_MAX env)
- keyGenerator: `req.body?.email || req.ip`

**Test:** T2.10

---

## Faz 2 Test Sonuçları

| Test | Adım | Beklenen | Sonuç |
|------|------|----------|-------|
| T2.1 | Login → Response'da token yok, Set-Cookie var | Cookie set, body'de user | Geçti |
| T2.2 | Token/cookie olmadan API isteği | 401 | Geçti |
| T2.3 | Cookie ile API isteği (credentials: include) | 200 | Geçti |
| T2.4 | Logout → Cookie temizlenir | clearCookie, 200 | Geçti |
| T2.5 | 6 karakter şifre ile kullanıcı oluştur | 400, doğrulama hatası | Geçti |
| T2.6 | 12+ karmaşık şifre ile kullanıcı oluştur | 201 | Geçti |
| T2.7 | 5 yanlış şifre → 6. deneme | 423, hesap kilitli | Geçti |
| T2.8 | 15 dk sonra tekrar giriş | Başarılı | Geçti |
| T2.9 | Access token süresi dolunca /auth/refresh | Yeni access_token cookie | Geçti |
| T2.10 | 6. login denemesi rate limit | 429 | Geçti |
| T2.11 | XSS: document.cookie veya localStorage.token | Token erişilemez (HttpOnly) | Geçti |

---

## Faz 2 Dosya Değişiklik Listesi

| Dosya | İşlem |
|-------|-------|
| `teftispro/backend/src/server.js` | cookie-parser, login cookie, authenticate, refresh, logout, passwordSchema, hesap kilitleme, login rate limit |
| `teftispro/backend/prisma/schema.prisma` | failedLoginAttempts, lockedUntil |
| `teftispro/frontend/public/layout.js` | apiFetch, logout güncelleme |
| `teftispro/frontend/public/login.html` | credentials, token kaldırma |
| `teftispro/frontend/public/*.html` | apiFetch, token kaldırma (12 sayfa) |
| `teftispro/frontend/index.html` | user kontrolü |

---

# Faz 3 — Frontend Güvenliği (XSS, CSRF, CSP)

> **ISO Referansları:** Ek A 8.28 (Güvenli Kodlama), Ek A 8.12 (Veri Sızıntısını Önleme)

---

## 3.1 XSS Koruması — DOMPurify Entegrasyonu

### Yapılan Değişiklikler

**Dosya:** `teftispro/frontend/public/js/security.js` (yeni)

- `safeText(dirty)`: Kullanıcı girdisini HTML escape eder (textContent → innerHTML)
- `safeHTML(dirty)`: Sınırlı HTML etiketlerine izin verir (b, i, em, strong, br, p, ul, ol, li); DOMPurify yoksa safeText kullanır

**DOMPurify CDN:** Tüm HTML sayfalarına DOMPurify 3.1.3 (cdnjs) SRI ile eklendi:
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.1.3/purify.min.js" integrity="sha384-SASP0Us+VO2lmZomWfdXP3ofWT1CyolTWk7JSru4UMryuaBT3woFsLawc75lz1Kn" crossorigin="anonymous"></script>
<script src="/public/js/security.js"></script>
```

**Test:** T3.1, T3.2, T3.3

---

## 3.2 innerHTML Kullanımlarının Denetimi

### Yapılan Değişiklikler

Tüm kullanıcı/API verisi içeren innerHTML kullanımları `safeText()` ile escape edildi:

| Dosya | Değişiklik |
|-------|------------|
| layout.js | toast message, getUserInitials, getUserName, getRoleDisplayName, breadcrumb, pageTitle |
| raporlar.html | c.name, e.name, audit.title, branch.name, user.email |
| sirket_yonetimi.html | u.email, c.name, c.owner.email |
| bolge_yonetimi.html | c.name, r.name, r.company?.name |
| kategori_yonetimi.html | cat.title, q.text, q.description, c.title |
| sube_yonetimi.html | c.name, r.name, b.name, b.city, b.region?.name, b.company?.name |
| admin_yonetimi.html | u.email, getRoleDisplayName(u.role) |
| denetim_cevaplama.html | b.name, cat.title, q.text, q.description, a.note |
| denetim_inceleme.html | cat.title, q.text, a.note, cat.title (tabCategories) |
| kontrol_paneli.html | audit.title, branch.name, user.email, getStatusName, u.email, b.name |
| denetim_listesi.html | audit.title, branch.name, user.email, getStatusName, ans.question?.text, ans.note, ans.question?.category?.title |

**Sabit HTML (spinner, boş durum):** Değişiklik yapılmadı.

---

## 3.3 Anti-CSRF Token Mekanizması

### Backend Değişiklikleri

**Dosya:** `teftispro/backend/src/server.js`

- `GET /auth/csrf-token`: 64 karakter rastgele token üretir, `csrf_token` cookie set eder (httpOnly: false, sameSite: strict)
- `validateCSRF` middleware: GET, HEAD, OPTIONS skip; POST, PUT, DELETE, PATCH için `cookie csrf_token === header X-CSRF-Token` doğrulaması
- CORS `allowedHeaders`'a `X-CSRF-Token` eklendi

### Frontend Değişiklikleri

**layout.js:**
- `apiFetch`: POST/PUT/DELETE/PATCH isteklerinde cookie'den `csrf_token` okuyup `X-CSRF-Token` header ekler
- `LAYOUT.init`: Sayfa yüklenince `GET /auth/csrf-token` çağrılır (cookie set)

**login.html:**
- Sayfa yüklenince `GET /auth/csrf-token` çağrılır
- Login submit'te: Token yoksa önce fetch, sonra `X-CSRF-Token` header ile POST /auth/login

**Test:** T3.4, T3.5, T3.6, T3.7

---

## 3.4 Subresource Integrity (SRI)

- **DOMPurify:** cdnjs üzerinden SRI sha384 hash ile yükleniyor
- **Tailwind:** Lokal build ile CDN kaldırıldı — SRI gerekmez
- **Google Fonts, Chart.js, jspdf, xlsx:** Mevcut CDN'ler; CSP'de izin verildi

---

## 3.5 Tailwind CSS Lokal Build

### Yapılan Değişiklikler

**Kurulum:**
```bash
cd teftispro/frontend
npm install -D tailwindcss@3
```

**Dosyalar:**
- `tailwind.config.js`: content: public/**/*.html, index.html; darkMode: class; accent renkleri, fontFamily
- `src/input.css`: @tailwind base/components/utilities
- `package.json`: `"build:css": "tailwindcss -i ./src/input.css -o ./public/tailwind.min.css --minify"`

**HTML Güncellemeleri:** Tüm sayfalarda `<script src="https://cdn.tailwindcss.com">` kaldırıldı, yerine `<link rel="stylesheet" href="/public/tailwind.min.css">` eklendi.

**layout.js:** `applyCSSVarTailwind` artık boş (config build-time'da uygulanıyor).

**Test:** T3.8, T3.9, T3.10

---

## 3.6 CSP Güncellemesi

**Dosya:** `teftispro/backend/src/server.js`

- `scriptSrc`: `https://cdn.tailwindcss.com` **kaldırıldı**
- `scriptSrc`: `https://cdnjs.cloudflare.com`, `https://cdn.jsdelivr.net`, `https://cdn.sheetjs.com` (CDN script'leri için)

---

## Faz 3 Test Sonuçları

| Test | Adım | Beklenen | Sonuç |
|------|------|----------|-------|
| T3.1 | Denetim notuna `<script>alert(1)</script>` yaz | Render'da script çalışmaz | Manuel test |
| T3.2 | Kategori başlığına `<img src=x onerror=alert(1)>` (admin) | Render'da çalışmaz | Manuel test |
| T3.3 | Toast mesajına `<b>test</b>` | safeText ile escape, HTML render edilmez | Manuel test |
| T3.4 | X-CSRF-Token olmadan POST /companies | 403 | Backend restart sonrası |
| T3.5 | Yanlış CSRF token ile POST | 403 | Backend restart sonrası |
| T3.6 | Geçerli token ile POST | 201 | Backend restart sonrası |
| T3.7 | Login sayfası → csrf-token alınır, login başarılı | Cookie set, login OK | Manuel test |
| T3.8 | `npm run build:css` | tailwind.min.css oluşur | Geçti |
| T3.9 | Tüm sayfalar doğru stil ile yüklenir | Görsel doğrulama | Manuel test |
| T3.10 | Dark mode, accent renkler çalışır | Görsel doğrulama | Manuel test |
| T3.11 | Mevcut işlevsellik bozulmamalı | Login, denetim, CRUD | Manuel test |

---

## Faz 3 Dosya Değişiklik Listesi

| Dosya | İşlem |
|-------|-------|
| `teftispro/frontend/public/js/security.js` | Yeni (safeText, safeHTML) |
| `teftispro/frontend/public/layout.js` | apiFetch CSRF, LAYOUT.init csrf fetch, applyCSSVarTailwind, safeText |
| `teftispro/frontend/public/login.html` | DOMPurify, security.js, CSRF token fetch, login X-CSRF-Token |
| `teftispro/frontend/public/*.html` (12 sayfa) | Tailwind CDN → link, DOMPurify, security.js, innerHTML safeText |
| `teftispro/frontend/index.html` | tailwind.min.css, DOMPurify, security.js |
| `teftispro/frontend/tailwind.config.js` | Yeni |
| `teftispro/frontend/src/input.css` | Yeni |
| `teftispro/frontend/package.json` | tailwindcss@3, build:css script |
| `teftispro/backend/src/server.js` | crypto, validateCSRF, /auth/csrf-token, CORS X-CSRF-Token, CSP |
| `teftispro/completedsecurity.md` | Faz 3 dokümantasyonu |

---

## Kurulum Notları (Faz 3)

1. `cd teftispro/frontend && npm run build:css` — Tailwind CSS derle
2. Backend'i yeniden başlat (CSRF değişiklikleri için)
3. `ALLOWED_ORIGINS` frontend URL'ini içermeli (örn. `http://localhost:2525`)

---

# Faz 4 — Backend Güvenliği ve Kriptografik Kontroller

> **ISO Referansları:** Ek A 8.24 (Kriptografi), Ek A 8.11 (Veri Maskeleme), Ek A 8.28 (Güvenli Kodlama)

---

## 4.1 Tüm Endpoint'lerde Zod Validasyon Zorunluluğu

### Yapılan Değişiklikler

**Yeni dosyalar:**
- `teftispro/backend/src/middleware/validate.js` — Merkezi `validate(schema)` middleware
- `teftispro/backend/src/schemas/common.js` — `parseId`, `passwordSchema`, `paramsIdSchema`, `paramsOnlySchema`
- `teftispro/backend/src/schemas/company.schema.js` — `updateCompanySchema`, `deleteCompanySchema`
- `teftispro/backend/src/schemas/branch.schema.js` — `updateBranchSchema`, `assignBranchSchema`
- `teftispro/backend/src/schemas/profile.schema.js` — `profileUpdateSchema`
- `teftispro/backend/src/schemas/correctiveAction.schema.js` — `correctiveActionCreateSchema`, `correctiveActionUpdateSchema`, `auditCorrectiveActionsSchema`
- `teftispro/backend/src/schemas/audit.schema.js` — `auditParamsSchema`, `auditAnswersSchema`, `auditReviewSchema`

**Validasyon eklenen endpoint'ler:**

| Endpoint | Şema |
|----------|------|
| DELETE /users/:id | paramsOnlySchema |
| PUT /companies/:id | updateCompanySchema |
| DELETE /companies/:id | deleteCompanySchema |
| DELETE /regions/:id | paramsOnlySchema |
| PUT /branches/:id | updateBranchSchema |
| DELETE /branches/:id | paramsOnlySchema |
| POST /branches/:id/assign | assignBranchSchema |
| DELETE /categories/:id | paramsOnlySchema |
| DELETE /questions/:id | paramsOnlySchema |
| PUT /profile | profileUpdateSchema |
| POST /corrective-actions | correctiveActionCreateSchema |
| PUT /corrective-actions/:id | correctiveActionUpdateSchema |
| GET /audits/:id | auditParamsSchema |
| POST /audits/:id/start | auditParamsSchema |
| POST /audits/:id/answers | auditAnswersSchema |
| POST /audits/:id/photos | auditParamsSchema |
| POST /audits/:id/signature | auditParamsSchema |
| POST /audits/:id/signatures | auditParamsSchema |
| POST /audits/:id/submit | auditParamsSchema |
| POST /audits/:id/review | auditReviewSchema |
| DELETE /audits/:id | auditParamsSchema |
| POST /audits/:id/corrective-actions | auditCorrectiveActionsSchema |
| GET /audits/:id/pdf | auditParamsSchema |
| GET /audits/:id/pdf-nonconformity | auditParamsSchema |
| POST /notifications/:id/read | paramsOnlySchema |
| GET /stats/branch/:id | paramsOnlySchema |

**Test:** T4.1, T4.2, T4.8

---

## 4.2 SQL Injection Koruması Doğrulaması

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/SECURITY.md` (yeni)

- Kod tabanında `$queryRaw`, `$executeRaw`, `$queryRawUnsafe` araması yapıldı — sonuç yok (Prisma ORM kullanılıyor)
- Raw SQL kullanım kuralı dokümante edildi: `prisma.$queryRaw` (tagged template) kullanılmalı, `$queryRawUnsafe` kullanılmamalı

---

## 4.3 Hassas Veri Maskeleme (Ek A 8.11)

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

- Prisma `$use` middleware eklendi — User modelinden dönen tüm sonuçlardan `password` alanı otomatik çıkarılır
- Login ve şifre doğrulama için `prismaWithPassword` adlı ayrı Prisma client kullanılır (bcrypt.compare için password gerekli)
- `prismaWithPassword` kullanılan yerler: `/auth/login`, `/auth/refresh`, `authenticate` middleware, `PUT /profile/password`

**Test:** T4.3

---

## 4.4 API Yanıtlarında Bilgi İfşası Önleme

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

- `app.disable('x-powered-by')` — Express sunucu imzası kaldırıldı
- Global error handler'a Prisma hata kodları eklendi:
  - `P2002` → 409 "Bu kayıt zaten mevcut"
  - `P2025` → 404 "Kayıt bulunamadı"
- `asyncHandler` helper tanımlandı (ileride kullanım için)

**Test:** T4.4, T4.5

---

## 4.5 Rate Limiting Genişletme

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/server.js`

| Limiter | Window | Max | Uygulandığı endpoint'ler |
|---------|--------|-----|--------------------------|
| uploadLimiter | 15 dk | 30 | POST /upload, POST /audits/:id/photos, POST /audits/:id/signatures |
| writeLimiter | 15 dk | 50 | POST/PUT/DELETE users, companies, regions, branches, categories, questions, audits, corrective-actions |

**Test:** T4.6, T4.7

---

## 4.6 server.js Modüler Yapıya Dönüştürme (Plan B)

### Yapılan Değişiklikler

- Middleware ayrı dosyaya taşındı: `middleware/validate.js`
- Şemalar ayrı modüllere taşındı: `schemas/common.js`, `schemas/company.schema.js`, `schemas/branch.schema.js`, `schemas/profile.schema.js`, `schemas/correctiveAction.schema.js`, `schemas/audit.schema.js`
- Route'lar `server.js` içinde kalmaya devam ediyor (tam modüler yapı ileride uygulanabilir)

---

## 4.7 TLS 1.2+ Zorunluluğu

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/.env.example`

- `TLS_KEY_PATH`, `TLS_CERT_PATH` yorum satırları eklendi
- Production'da reverse proxy (nginx) kullanılıyorsa boş bırakılır
- Node.js doğrudan HTTPS sunacaksa path'ler tanımlanır

---

## Faz 4 Test Sonuçları

| Test | Adım | Beklenen | Sonuç |
|------|------|----------|-------|
| T4.1 | PUT /companies/abc (geçersiz id) | 400 Doğrulama hatası | Geçti |
| T4.2 | PUT /companies/1 body: { name: "" } | 400 | Geçti |
| T4.3 | GET /users response'da password alanı | Yok | Geçti |
| T4.4 | Response header X-Powered-By | Yok | Geçti |
| T4.5 | Prisma P2002 (duplicate email) | 409 "Bu kayıt zaten mevcut" | Doğrulanacak |
| T4.6 | 31. dosya yükleme denemesi (15 dk içinde) | 429 | Doğrulanacak |
| T4.7 | 51. write işlemi (15 dk içinde) | 429 | Doğrulanacak |
| T4.8 | Geçerli validasyon ile PUT /companies/1 | 200 | Geçti |

---

## Faz 4 Dosya Değişiklik Listesi

| Dosya | İşlem |
|-------|-------|
| `teftispro/backend/src/middleware/validate.js` | Yeni |
| `teftispro/backend/src/schemas/common.js` | Yeni |
| `teftispro/backend/src/schemas/company.schema.js` | Yeni |
| `teftispro/backend/src/schemas/branch.schema.js` | Yeni |
| `teftispro/backend/src/schemas/profile.schema.js` | Yeni |
| `teftispro/backend/src/schemas/correctiveAction.schema.js` | Yeni |
| `teftispro/backend/src/schemas/audit.schema.js` | Yeni |
| `teftispro/backend/src/server.js` | Prisma middleware, x-powered-by, validate, schemas, rate limiters, endpoint validasyonları |
| `teftispro/backend/.env.example` | TLS_KEY_PATH, TLS_CERT_PATH |
| `teftispro/backend/SECURITY.md` | Yeni (SQL injection kuralı) |
| `teftispro/completedsecurity.md` | Faz 4 dokümantasyonu |

---

## Kurulum Notları (Faz 4)

1. Backend'i yeniden başlatın
2. Validasyon testleri için geçersiz ID (örn. `PUT /companies/abc`) veya boş zorunlu alan gönderin
3. Rate limit testleri için 15 dakika içinde 31 dosya yükleme veya 51 write işlemi deneyin

---

# Faz 5 — Loglama, İzleme ve Denetim İzleri

> **ISO Referansları:** Ek A 8.15 (Loglama), Ek A 8.16 (İzleme Faaliyetleri), Ek A 8.17 (Saat Senkronizasyonu)

---

## 5.1 Yapılandırılmış JSON Loglama (Morgan → Winston)

### Yapılan Değişiklikler

**Paketler:**
- `winston`, `winston-daily-rotate-file`, `express-winston` kuruldu
- `morgan` kaldırıldı

**Dosya:** `teftispro/backend/src/logger.js` (yeni)

- Winston logger: JSON format, timestamp, defaultMeta `{ service: 'teftispro-api' }`
- Transport'lar:
  - `logs/error-%DATE%.log` — sadece error (maxSize 20m, maxFiles 365d, zippedArchive)
  - `logs/combined-%DATE%.log` — tüm seviyeler (maxSize 50m, maxFiles 365d)
- Development: Console (colorize, simple format)
- `LOG_LEVEL`, `LOG_RETENTION_DAYS` ortam değişkenleri

**Dosya:** `teftispro/backend/src/server.js`

- `app.use(morgan('dev'))` kaldırıldı
- `expressWinston.logger` eklendi — HTTP istekleri JSON loglanıyor
- dynamicMeta: `userId`, `userEmail`, `ip`, `userAgent`
- Tüm `console.error` (hata logları) → `logger.error`

**Test:** T5.1, T5.2

---

## 5.2 Denetim İzi (Audit Trail) Sistemi

### Yapılan Değişiklikler

**Prisma schema:** `AuditLog` modeli eklendi

```prisma
model AuditLog {
  id          Int      @id @default(autoincrement())
  timestamp   DateTime @default(now())
  userId      Int?
  userEmail   String?
  action      String   // CREATE, UPDATE, DELETE, LOGIN, LOGIN_FAILED, LOGOUT, ACCESS_DENIED, RATE_LIMIT, CSRF_FAILED
  resource    String
  resourceId  String?
  oldValue    String?  // JSON
  newValue    String?  // JSON
  ipAddress   String?
  userAgent   String?
  details     String?
}
```

**Dosya:** `teftispro/backend/src/audit.js` (yeni)

- `createAuditLog(opts)` — AuditLog kaydı oluşturur, hata durumunda logger.error
- `sanitizeLogData(data)` — password, token vb. hassas alanları `[REDACTED]` yapar
- `maskEmail(email)` — e-posta kısmen maskeleme (LOGIN_FAILED için)

**Denetim izi entegrasyonu — Kritik endpoint'ler:**

| Endpoint | Action | Resource |
|----------|--------|----------|
| POST /auth/login (başarılı) | LOGIN | User |
| POST /auth/login (başarısız/kilitli) | LOGIN_FAILED | User |
| POST /auth/logout | LOGOUT | User |
| POST /auth/refresh | LOGIN | User (details: Token yenilendi) |
| POST /users | CREATE | User |
| DELETE /users/:id | DELETE | User |
| POST/PUT/DELETE companies, regions, branches | CREATE/UPDATE/DELETE | Company, Region, Branch |
| POST /branches/:id/assign | UPDATE | Branch (details: Şube ataması) |
| POST/DELETE categories, questions | CREATE/DELETE | Category, Question |
| POST /audits | CREATE | Audit |
| POST /audits/:id/start | UPDATE | Audit (details: Denetim başlatıldı) |
| POST /audits/:id/submit | UPDATE | Audit (details: Denetim gönderildi) |
| POST /audits/:id/review | UPDATE | Audit |
| DELETE /audits/:id | DELETE | Audit |
| POST /corrective-actions | CREATE | CorrectiveAction |
| PUT /corrective-actions/:id | UPDATE | CorrectiveAction |
| PUT /profile | UPDATE | Profile |
| PUT /profile/password | UPDATE | Profile (details: Şifre değiştirildi) |
| POST /upload | CREATE | File |

**Middleware seviyesinde:**
- `authenticate` (401): ACCESS_DENIED — Auth
- `authorize` (403): ACCESS_DENIED — endpoint path
- `validateCSRF` (403): CSRF_FAILED — Auth
- Rate limit (429): RATE_LIMIT — API, Auth, Upload, Write

**Test:** T5.3, T5.4, T5.5, T5.6, T5.7, T5.8, T5.9, T5.10

---

## 5.3 PII Sızıntı Önleme (5.4)

### Yapılan Değişiklikler

**Dosya:** `teftispro/backend/src/audit.js`

- `SENSITIVE_KEYS`: password, token, secret, authorization, cookie, access_token, refresh_token, csrf_token
- `sanitizeLogData()` — nesne içindeki hassas anahtarları `[REDACTED]` yapar, recursive
- `createAuditLog` içinde `oldValue` ve `newValue` JSON'a çevrilmeden önce sanitize edilir

**Test:** T5.11

---

## 5.4 Log Saklama ve .env (5.6)

### Yapılan Değişiklikler

- `.env.example`: `LOG_LEVEL=info`, `LOG_RETENTION_DAYS=365`
- `.gitignore`: `teftispro/backend/logs/` eklendi
- Winston DailyRotateFile: `maxFiles: '365d'` (12 ay saklama)

---

## Faz 5 Test Sonuçları

| Test | Adım | Beklenen | Sonuç |
|------|------|----------|-------|
| T5.1 | Sunucu başlat | logs/combined-*.log, logs/error-*.log oluşur | Geçti |
| T5.2 | GET /auth/csrf-token | combined log'da HTTP 200, JSON format | Geçti |
| T5.3 | Başarılı login | AuditLog'da LOGIN, userId, ipAddress | Geçti |
| T5.4 | Başarısız login | AuditLog'da LOGIN_FAILED, details (email maskele) | Geçti |
| T5.5 | Logout | AuditLog'da LOGOUT | Geçti |
| T5.6 | POST /users (admin) | AuditLog'da CREATE, resource: User | Geçti |
| T5.7 | DELETE /companies/:id | AuditLog'da DELETE, resource: Company | Geçti |
| T5.8 | POST /audits/:id/review (onay) | AuditLog'da UPDATE, oldValue/newValue status | Geçti |
| T5.9 | Token olmadan API isteği | AuditLog'da ACCESS_DENIED | Geçti |
| T5.10 | Geçersiz CSRF ile POST | AuditLog'da CSRF_FAILED | Geçti |
| T5.11 | oldValue içinde password | sanitizeLogData ile [REDACTED] veya çıkarılmış | Geçti |

---

## Faz 5 Dosya Değişiklik Listesi

| Dosya | İşlem |
|-------|-------|
| `teftispro/backend/package.json` | winston, winston-daily-rotate-file, express-winston; morgan kaldırıldı |
| `teftispro/backend/src/logger.js` | Yeni — Winston yapılandırması |
| `teftispro/backend/src/audit.js` | Yeni — createAuditLog, sanitizeLogData, maskEmail |
| `teftispro/backend/prisma/schema.prisma` | AuditLog modeli |
| `teftispro/backend/prisma/migrations/20260305191237_add_audit_log/` | Migration |
| `teftispro/backend/src/server.js` | Morgan→express-winston, createAuditLog tüm kritik endpoint'lerde, rate limit handler, authenticate/authorize/validateCSRF audit log, logger.error |
| `teftispro/backend/.env.example` | LOG_LEVEL, LOG_RETENTION_DAYS |
| `.gitignore` | teftispro/backend/logs/ |
| `teftispro/completedsecurity.md` | Faz 5 dokümantasyonu |

---

## Kurulum Notları (Faz 5)

1. Backend'i yeniden başlatın
2. `logs/` dizini otomatik oluşturulur
3. AuditLog sorgusu: `sqlite3 prisma/dev.db "SELECT * FROM AuditLog ORDER BY id DESC LIMIT 20;"`
4. Log dosyaları: `logs/combined-YYYY-MM-DD.log`, `logs/error-YYYY-MM-DD.log`
