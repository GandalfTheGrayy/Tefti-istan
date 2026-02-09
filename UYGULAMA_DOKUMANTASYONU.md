# TeftişPro - Teftiş ve Kalite Kontrol Uygulaması Tam Dokümantasyonu

Bu dokümantasyon, TeftişPro uygulamasının birebir aynısını sıfırdan oluşturabilmeniz için gereken tüm teknik detayları içermektedir.

---

## 📌 İçindekiler

1. [Teknoloji Yığını (Tech Stack)](#1-teknoloji-yığını)
2. [Proje Yapısı](#2-proje-yapısı)
3. [Veritabanı Şeması](#3-veritabanı-şeması)
4. [API Endpoint'leri](#4-api-endpointleri)
5. [Kullanıcı Rolleri ve Yetkiler](#5-kullanıcı-rolleri-ve-yetkiler)
6. [Frontend Sayfaları](#6-frontend-sayfaları)
7. [İş Akışları ve Senaryolar](#7-iş-akışları-ve-senaryolar)
8. [Puanlama Sistemi](#8-puanlama-sistemi)
9. [Kurulum Kılavuzu](#9-kurulum-kılavuzu)

---

## 1. Teknoloji Yığını

### Backend
| Teknoloji | Versiyon | Amaç |
|-----------|----------|------|
| Node.js | - | Runtime |
| Express.js | ^4.21.1 | Web framework |
| Prisma | ^5.22.0 | ORM |
| SQLite | - | Veritabanı (dev.db) |
| bcryptjs | ^2.4.3 | Şifre hashleme |
| jsonwebtoken | ^9.0.2 | JWT token yönetimi |
| zod | ^3.23.8 | Validasyon |
| multer | ^1.4.5 | Dosya yükleme |
| helmet | ^8.0.0 | Güvenlik |
| cors | ^2.8.5 | Cross-origin |
| morgan | ^1.10.0 | Logging |
| express-rate-limit | ^7.4.0 | Rate limiting |

### Frontend
| Teknoloji | Versiyon | Amaç |
|-----------|----------|------|
| Vite | ^7.1.5 | Build tool |
| TailwindCSS | CDN | Stil |
| Vanilla JavaScript | ES6+ | Mantık |
| Material Symbols | CDN | İkonlar |
| Inter Font | Google Fonts | Tipografi |

---

## 2. Proje Yapısı

```
teftişistan/
├── server.js                    # Ana backend sunucu dosyası
├── teftisistanBE/
│   ├── package.json
│   ├── prisma/
│   │   ├── schema.prisma        # Veritabanı şeması
│   │   ├── dev.db               # SQLite veritabanı
│   │   └── migrations/          # Migrasyon dosyaları
│   └── src/
│       └── server.js            # Backend server (daha detaylı)
├── teftisistanFE/
│   ├── package.json
│   ├── index.html               # Ana giriş (login'e yönlendirir)
│   ├── vite.config.js
│   └── public/
│       ├── login.html
│       ├── kontrol_paneli_(dashboard)__10.html
│       ├── denetim_cevaplama_sayfası_11.html
│       ├── denetim_listesi_sayfası_11.html
│       ├── denetim_i̇nceleme_sayfası_14.html
│       ├── admin_yönetim_sayfası_6.html
│       ├── şirket_yönetimi_3.html
│       ├── şube_yönetimi_3.html
│       ├── bölge_yönetimi_2.html
│       ├── raporlar_sayfası_12.html
│       ├── profil__hesap_ayarları_3.html
│       ├── yeni_kategori_ekle_16.html
│       ├── bildirimler_sayfası_3.html
│       ├── kayıt_(sign_up)_sayfası_2.html
│       └── şifre_sıfırlama_sayfası_2.html
└── uploads/                     # Dosya yükleme dizini
```

---

## 3. Veritabanı Şeması

### 3.1 Role (Rol)
```prisma
model Role {
  id    Int       @id @default(autoincrement())
  name  String    @unique  // admin, planlamacı, field, gözden_geçiren, firma_sahibi
  users User[]
}
```

### 3.2 User (Kullanıcı)
```prisma
model User {
  id                Int       @id @default(autoincrement())
  email             String    @unique
  password          String    // bcrypt ile hashlenmiş
  roleId            Int
  role              Role      @relation(fields: [roleId], references: [id])
  
  // Profil bilgileri
  profilePhoto      String?   // Profil fotoğrafı URL
  signatureUrl      String?   // Önceden tanımlı imza URL
  
  // Müşteri bağlantısı
  companyId         Int?      // Hangi şirkete ait
  branchId          Int?      // Hangi şubeye ait
  
  // İlişkiler
  audits            Audit[]
  reviews           Audit[]   @relation("ReviewRelation")
  branchAssignments BranchAssignment[]
  ownedCompanies    Company[] @relation("CompanyOwner")
}
```

### 3.3 Company (Şirket)
```prisma
model Company {
  id        Int       @id @default(autoincrement())
  name      String    @unique
  createdAt DateTime  @default(now())
  
  // İlişkiler
  branches  Branch[]
  audits    Audit[]
  regions   Region[]
  
  // Şirket sahibi
  ownerId   Int?
  owner     User?     @relation("CompanyOwner", fields: [ownerId], references: [id])
}
```

### 3.4 Region (Bölge)
```prisma
model Region {
  id        Int      @id @default(autoincrement())
  name      String
  companyId Int
  company   Company  @relation(fields: [companyId], references: [id])
  branches  Branch[]
}
```

### 3.5 Branch (Şube)
```prisma
model Branch {
  id          Int                 @id @default(autoincrement())
  name        String
  city        String
  isActive    Boolean             @default(true)
  companyId   Int
  company     Company             @relation(fields: [companyId], references: [id])
  regionId    Int?
  region      Region?             @relation(fields: [regionId], references: [id])
  
  audits      Audit[]
  assignments BranchAssignment[]
}
```

### 3.6 Category (Kategori)
```prisma
model Category {
  id        Int        @id @default(autoincrement())
  title     String     // Örn: "Genel Temizlik", "Yangın Güvenliği"
  questions Question[]
}
```

### 3.7 Question (Soru)
```prisma
model Question {
  id           Int       @id @default(autoincrement())
  text         String    // Soru metni
  description  String?   // Detaylı açıklama
  points       Int       @default(5)  // Puan değeri
  noteRequired Boolean   @default(false)  // Açıklama zorunlu mu?
  categoryId   Int
  category     Category  @relation(fields: [categoryId], references: [id])
  
  answers      Answer[]
  photos       Photo[]
}
```

### 3.8 Audit (Denetim)
```prisma
model Audit {
  id                 Int       @id @default(autoincrement())
  userId             Int       // Denetçi
  user               User      @relation(fields: [userId], references: [id])
  reviewerId         Int?      // Onaylayan
  reviewer           User?     @relation("ReviewRelation", fields: [reviewerId], references: [id])
  status             String    @default("draft")  
  // Durumlar: draft, submitted, approved, rejected, revision_requested
  createdAt          DateTime  @default(now())
  deletedAt          DateTime? // Soft delete
  
  companyId          Int?
  company            Company?  @relation(fields: [companyId], references: [id])
  branchId           Int?
  branch             Branch?   @relation(fields: [branchId], references: [id])
  
  // Denetim döngüsü
  nextAuditDate      DateTime?
  
  // Rapor bilgileri
  authorizedPerson   String?   // Yetkili kişi adı
  clientSignatureUrl String?   // Karşı taraf imza URL
  revisionNote       String?   // Revizyon talebi notu
  
  answers            Answer[]
  photos             Photo[]
}
```

### 3.9 Answer (Cevap)
```prisma
model Answer {
  id         Int      @id @default(autoincrement())
  auditId    Int
  questionId Int
  value      String   // U (Uygun), YP (Yarı Puanlı), UD (Uygun Değil), DD (Değerlendirme Dışı)
  note       String?  // Açıklama/not
  
  audit      Audit    @relation(fields: [auditId], references: [id])
  question   Question @relation(fields: [questionId], references: [id])
  
  @@unique([auditId, questionId], name: "auditId_questionId")
}
```

### 3.10 Photo (Fotoğraf)
```prisma
model Photo {
  id         Int       @id @default(autoincrement())
  auditId    Int
  questionId Int?      // null ise imza fotoğrafı
  url        String
  createdAt  DateTime  @default(now())
  
  audit      Audit     @relation(fields: [auditId], references: [id])
  question   Question? @relation(fields: [questionId], references: [id])
}
```

### 3.11 BranchAssignment (Şube Ataması)
```prisma
model BranchAssignment {
  id        Int      @id @default(autoincrement())
  branchId  Int
  userId    Int      // Denetçi
  createdAt DateTime @default(now())
  
  branch Branch @relation(fields: [branchId], references: [id])
  user   User   @relation(fields: [userId], references: [id])
  
  @@unique([branchId, userId])
}
```

---

## 4. API Endpoint'leri

### 4.1 Kimlik Doğrulama

#### POST /auth/login
**Amaç:** Kullanıcı girişi

**Request Body:**
```json
{
  "email": "saha@demo.local",
  "password": "Field123!"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "saha@demo.local",
    "role": "field"
  }
}
```

**Rate Limit:** 20 istek / 10 dakika

#### GET /auth/me
**Amaç:** Mevcut kullanıcı bilgisi
**Header:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "id": 1,
  "email": "saha@demo.local",
  "role": "field"
}
```

---

### 4.2 Şirketler

#### GET /companies
**Yetki:** admin, planlamacı
**Response:** Tüm şirketler listesi (regions, branches dahil)

#### POST /companies
**Yetki:** admin
**Request Body:**
```json
{
  "name": "Yeni Şirket A.Ş."
}
```

---

### 4.3 Bölgeler

#### GET /regions
**Yetki:** admin, planlamacı
**Response:** Tüm bölgeler (company, branches dahil)

#### POST /regions
**Yetki:** admin
**Request Body:**
```json
{
  "name": "Marmara Bölgesi",
  "companyId": 1
}
```

---

### 4.4 Şubeler

#### GET /branches
**Yetki:** Tüm kullanıcılar (rol bazlı filtreleme var)
**Query Params:** `regionId` (opsiyonel)

**Önemli Mantık:**
- `field` rolündeki kullanıcılar sadece atandığı şubeleri görür
- Diğer roller tüm şubeleri görür

#### POST /branches
**Yetki:** admin
**Request Body:**
```json
{
  "name": "Kadıköy Şubesi",
  "city": "İstanbul",
  "regionId": 1
}
```

---

### 4.5 Kategoriler

#### GET /categories
**Yetki:** Tüm kullanıcılar
**Response:** Tüm kategoriler ve soruları

---

### 4.6 Kullanıcılar

#### GET /users
**Yetki:** admin, planlamacı
**Query Params:** `role` (opsiyonel, örn: field)

**Response:**
```json
[
  { "id": 1, "email": "admin@demo.local", "role": "admin" },
  { "id": 2, "email": "saha@demo.local", "role": "field" }
]
```

---

### 4.7 Denetimler

#### GET /audits
**Yetki:** Tüm kullanıcılar (rol bazlı filtreleme)
**Query Params:** `status` (opsiyonel)

**Önemli Mantık:**
- `field` rolündeki kullanıcılar sadece kendi denetimlerini görür
- Diğer roller tüm denetimleri görür
- Her denetim için skor hesaplanır

**Response:**
```json
[
  {
    "id": 1,
    "status": "draft",
    "createdAt": "2024-01-15T10:00:00Z",
    "user": { "id": 2, "email": "saha@demo.local" },
    "branch": { "id": 1, "name": "Kadıköy", "company": { "name": "ABC Ltd" } },
    "score": {
      "totalPoints": 100,
      "earnedPoints": 85,
      "percent": 85,
      "byCategory": [...]
    }
  }
]
```

#### GET /audits/:id
**Yetki:** Tüm kullanıcılar (rol bazlı erişim kontrolü)

**Response:**
```json
{
  "audit": {
    "id": 1,
    "status": "draft",
    "answers": [...],
    "photos": [...],
    "branch": {...},
    "company": {...},
    "user": {...}
  },
  "score": {
    "totalPoints": 100,
    "earnedPoints": 85,
    "percent": 85,
    "byCategory": [...]
  }
}
```

#### POST /audits
**Yetki:** admin, planlamacı
**Açıklama:** Yeni denetim oluşturur

**Request Body:**
```json
{
  "userId": 2,      // Denetçi ID (opsiyonel, varsayılan: mevcut kullanıcı)
  "branchId": 1     // Şube ID (opsiyonel)
}
```

#### POST /audits/:id/answers
**Yetki:** Denetim sahibi, sadece draft durumunda

**Request Body:**
```json
{
  "items": [
    { "questionId": 1, "value": "U", "note": "" },
    { "questionId": 2, "value": "UD", "note": "Zemin ıslaktı" }
  ]
}
```

**Cevap Değerleri:**
| Değer | Anlam | Puan Çarpanı |
|-------|-------|--------------|
| U | Uygun | 1 (100%) |
| YP | Yarı Puanlı | 0.5 (50%) |
| UD | Uygun Değil | 0 (0%) |
| DD | Değerlendirme Dışı | Puanlama dışı |

#### POST /audits/:id/photos
**Yetki:** Denetim sahibi, sadece draft durumunda
**Content-Type:** multipart/form-data

**Form Data:**
- `file`: Fotoğraf dosyası
- `questionId`: Soru ID (opsiyonel)

#### POST /audits/:id/submit
**Yetki:** Denetim sahibi
**Açıklama:** Denetimi gönderir (status: submitted)

#### POST /audits/:id/review
**Yetki:** gözden_geçiren, admin
**Açıklama:** Denetimi onaylar veya reddeder

**Request Body:**
```json
{
  "action": "approve",  // veya "reject"
  "note": "..."
}
```

#### POST /audits/:id/signature
**Yetki:** Denetim sahibi
**Açıklama:** Denetçi imzasını kaydeder

**Request Body:**
```json
{
  "dataUrl": "data:image/png;base64,..."
}
```

---

## 5. Kullanıcı Rolleri ve Yetkiler

| Rol | Açıklama | Yetkiler |
|-----|----------|----------|
| **admin** | Sistem yöneticisi | Tam erişim: kullanıcı, şirket, şube, bölge, kategori, denetim yönetimi |
| **planlamacı** | Denetim planlayıcı | Denetim oluşturma, denetçi atama, şube/bölge görme, raporlar |
| **field** | Saha denetçisi | Sadece atandığı şubelerde denetim yapma, fotoğraf yükleme, imza |
| **gözden_geçiren** | Onay yetkisi | Denetimleri onaylama/reddetme |
| **firma_sahibi** | Müşteri | Kendi şirketinin denetimlerini read-only görme |

---

## 6. Frontend Sayfaları

### 6.1 login.html - Giriş Sayfası
**Route:** `/login.html`

**Özellikler:**
- E-posta ve şifre girişi
- Şifre göster/gizle toggle
- Hata mesajı gösterimi
- jwt token localStorage'a kaydedilir
- Başarılı girişte dashboard'a yönlendirilir

**Tailwind Config:**
```javascript
{
  colors: {
    primary: '#13ec5b',
    'background-dark': '#102216',
  }
}
```

---

### 6.2 kontrol_paneli_(dashboard)__10.html - Dashboard
**Route:** `/kontrol_paneli_(dashboard)__10.html`

**Özellikler:**
- Sidebar navigasyon (rol bazlı görünürlük)
- İstatistik kartları (Atanmış Denetimler, Bekleyen Görevler, Tamamlanma Oranı)
- Denetim puanlama eğilim grafiği (SVG)
- Denetim listesi
- Mobil hamburger menü
- Bildirim sayacı
- Arama fonksiyonelliği

**Rol Bazlı UI:**
- `field`: "Yeni Denetim Başlat" butonu gizli, Planlama/Kullanıcı menüsü gizli
- `firma_sahibi`: Read-only mod, bazı menüler gizli
- `admin`: Tüm menüler görünür

**API Çağrıları:**
1. `GET /auth/me` - Kullanıcı bilgisi
2. `GET /audits` - Denetim listesi
3. `GET /stats/overview` - İstatistikler (opsiyonel)
4. `GET /stats/annual` - Grafik verisi (opsiyonel)

---

### 6.3 denetim_cevaplama_sayfası_11.html - Denetim Doldurma
**Route:** `/denetim_cevaplama_sayfası_11.html?id=<auditId>`

**Özellikler:**
- Kategori bazlı soru listesi (accordion)
- Her soru için: Evet (U), Hayır (UD), U/D (DD) butonları
- Açıklama textarea (UD seçildiğinde zorunlu)
- Fotoğraf yükleme (soru bazlı)
- İmza modal (canvas tabanlı)
- Otomatik kaydetme durumu göstergesi
- Progress bar (puan yüzdesi)

**İmza Özellikleri:**
- Canvas üzerine mouse/touch ile çizim
- Temizle butonu
- "Onayla ve Gönder" butonu
- PNG olarak base64 encode edilerek gönderilir

**API Çağrıları:**
1. `GET /audits/:id` - Denetim detayı
2. `GET /categories` - Kategoriler ve sorular
3. `POST /audits/:id/answers` - Cevap kaydetme
4. `POST /audits/:id/photos` - Fotoğraf yükleme
5. `POST /audits/:id/signature` - İmza kaydetme
6. `POST /audits/:id/submit` - Denetimi gönderme

---

### 6.4 denetim_listesi_sayfası_11.html - Denetim Listesi
**Route:** `/denetim_listesi_sayfası_11.html`

**Özellikler:**
- Arama fonksiyonu
- Filtreleme (Durum, Tarih, Sorumlu Kişi)
- Data table (ID, Başlık, Durum, Sorumlu, Tarih, Lokasyon)
- CSV export
- Yeni denetim ekleme
- Admin için silme butonu
- Pagination

**Durum Badge'leri:**
- Tamamlandı: Yeşil
- Gözden Geçiriliyor: Mavi
- Revizyon: Turuncu
- Taslak: Gri

---

### 6.5 denetim_i̇nceleme_sayfası_14.html - Denetim İnceleme
**Route:** `/denetim_i̇nceleme_sayfası_14.html?id=<auditId>`

**Özellikler:**
- Denetim özeti
- Puan analizi (dairesel progress)
- Kategori bazlı cevap görüntüleme
- Fotoğraf görüntüleme
- Tab navigasyonu (Tüm Cevaplar, Sadece Sorunlular, Fotoğraflar)
- Paylaş modal (WhatsApp, E-posta, Link kopyala)
- Onayla/Reddet butonları (gözden_geçiren/admin için)

**API Çağrıları:**
1. `GET /audits/:id`
2. `GET /categories`
3. `POST /audits/:id/review`

---

### 6.6 admin_yönetim_sayfası_6.html - Kullanıcı Yönetimi
**Route:** `/admin_yönetim_sayfası_6.html`
**Yetki:** admin

**Özellikler:**
- Kullanıcı listesi tablosu
- Yeni kullanıcı ekleme modal
- Kullanıcı silme
- Rol dropdown (admin, planlamacı, field, gözden_geçiren, firma_sahibi)

---

### 6.7 şirket_yönetimi_3.html - Şirket Yönetimi
**Route:** `/şirket_yönetimi_3.html`
**Yetki:** admin

**Özellikler:**
- Yeni şirket ekleme formu
- Kayıtlı şirketler tablosu
- Şirket silme
- Firma sahibi atama

---

### 6.8 şube_yönetimi_3.html - Şube Yönetimi
**Route:** `/şube_yönetimi_3.html`

**Özellikler:**
- Şirket/Bölge/Şehir dropdown
- Şube adı, telefon, e-posta, adres alanları
- Mevcut şubeler tablosu
- Arama fonksiyonu
- Düzenleme/Silme butonları

---

### 6.9 bölge_yönetimi_2.html - Bölge Yönetimi
**Route:** `/bölge_yönetimi_2.html`

**Özellikler:**
- Şirket dropdown
- Bölge adı girişi
- Şehir atama (dropdown + ekleme butonu)
- Atanmış şehirler listesi
- Mevcut bölgeler tablosu

---

### 6.10 raporlar_sayfası_12.html - Raporlar
**Route:** `/raporlar_sayfası_12.html`

**Özellikler:**
- Toplam rapor, ortalama başarı, en iyi şube istatistikleri
- Arama
- Rapor kartları grid (şube, şirket, puan, tarih)
- CSV indirme
- Rapor detayına gitmek için tıklama

---

### 6.11 profil__hesap_ayarları_3.html - Hesap Ayarları
**Route:** `/profil__hesap_ayarları_3.html`

**Özellikler:**
- Profil fotoğrafı değiştirme
- Kullanıcı adı ve e-posta görüntüleme
- Şifre değiştirme
- Bildirim tercihleri (toggle switch)
- Dil seçimi
- Tema seçimi (renk paletleri)

---

### 6.12 yeni_kategori_ekle_16.html - Soru Yönetimi
**Route:** `/yeni_kategori_ekle_16.html`

**Özellikler:**
- Kategori dropdown
- Soru metni textarea
- Görsel yükleme
- Cevap tipi seçimi (U, Y, UD, D)
- Mevcut sorular listesi
- Düzenleme/Silme

---

## 7. İş Akışları ve Senaryolar

### 7.1 Senaryo: Yeni Denetim Yapma (Saha Denetçisi)

```
1. Saha denetçisi login.html'den giriş yapar
   ↓
2. Dashboard'a yönlendirilir
   ↓
3. Atandığı şubeleri görür (sidebar: Denetimler)
   ↓
4. Admin/Planlamacı tarafından oluşturulan denetimi seçer
   ↓
5. denetim_cevaplama_sayfası_11.html açılır
   ↓
6. Kategoriler accordion olarak görünür
   ↓
7. Her soru için:
   - Evet (U), Hayır (UD) veya U/D (DD) seçer
   - UD seçerse zorunlu açıklama yazar
   - Opsiyonel olarak fotoğraf yükler
   ↓
8. Tüm sorular tamamlandığında "Denetimi Gönder" tıklar
   ↓
9. İmza modal açılır
   ↓
10. Canvas üzerine imza atar
    ↓
11. "Onayla ve Gönder" tıklar
    ↓
12. Denetim durumu: submitted
    ↓
13. Dashboard'a yönlendirilir
```

### 7.2 Senaryo: Denetim Onaylama (Gözden Geçiren)

```
1. Gözden geçiren giriş yapar
   ↓
2. Dashboard'da "Gözden Geçiriliyor" durumundaki denetimleri görür
   ↓
3. Denetim kartına tıklar
   ↓
4. denetim_inceleme_sayfası_14.html açılır
   ↓
5. Tüm cevapları, notları, fotoğrafları inceler
   ↓
6. Puan analizini görür
   ↓
7. İki seçenek:
   a) "Onayla" → status: approved
   b) "Reddet" → revizyon sebebi girer → status: rejected/revision_requested
   ↓
8. Sayfa yenilenir, durum güncellenir
```

### 7.3 Senaryo: Yeni Kullanıcı Ekleme (Admin)

```
1. Admin giriş yapar
   ↓
2. Sidebar: Kullanıcı Yönetimi tıklar
   ↓
3. admin_yönetim_sayfası_6.html açılır
   ↓
4. "Yeni Kullanıcı Ekle" butonuna tıklar
   ↓
5. Modal açılır:
   - E-posta
   - Şifre
   - Rol seçimi
   - Şirket ID (opsiyonel)
   ↓
6. "Kaydet" tıklar
   ↓
7. POST /users → kullanıcı oluşturulur
   ↓
8. Tablo güncellenir
```

### 7.4 Senaryo: Şirket ve Şube Oluşturma (Admin)

```
1. Admin giriş yapar
   ↓
2. Sidebar: Planlama → Şirketler tıklar
   ↓
3. şirket_yönetimi_3.html açılır
   ↓
4. "Yeni Şirket Ekle" formunu doldurur
   - Şirket Adı
   - Logo URL (opsiyonel)
   - Firma Sahibi ID (opsiyonel)
   ↓
5. "Kaydet" tıklar → POST /companies
   ↓
6. Bölge oluşturma: bölge_yönetimi_2.html
   - Şirket seçilir
   - Bölge adı girilir
   - Şehirler atanır
   ↓
7. Şube oluşturma: şube_yönetimi_3.html
   - Şirket seçilir
   - Bölge seçilir
   - Şube detayları girilir
   ↓
8. POST /branches → şube oluşturulur
```

### 7.5 Senaryo: Denetim Planlama (Planlamacı)

```
1. Planlamacı giriş yapar
   ↓
2. Dashboard'da "Yeni Denetim Başlat" tıklar
   ↓
3. POST /audits → yeni denetim oluşturulur
   ↓
4. Denetim cevaplama sayfasına yönlendirilir
   ↓
5. Şube seçimi yapılır (veya önceden atanır)
   ↓
6. Denetçi ataması yapılır (BranchAssignment)
   ↓
7. Atanan denetçi dashboard'ında bu denetimi görür
```

### 7.6 Senaryo: Firma Sahibi Rapor Görüntüleme

```
1. Firma sahibi giriş yapar
   ↓
2. Dashboard "Müşteri Portalı" modunda açılır
   ↓
3. Sadece kendi şirketine ait denetimleri görür
   ↓
4. Raporlar sayfasına gidebilir
   ↓
5. Read-only olarak denetim detaylarını inceleyebilir
   ↓
6. CSV indirebilir
```

---

## 8. Puanlama Sistemi

### 8.1 Puan Hesaplama Formülü

```javascript
const SCORE_MAP = { U: 1, YP: 0.5, UD: 0, DD: 0 }

// DD (Değerlendirme Dışı) cevaplar puanlama dışında bırakılır
const effectiveAnswers = audit.answers.filter(a => a.value !== 'DD')

// Toplam puan: tüm soruların puan toplamı
const totalPoints = effectiveAnswers.reduce((s, a) => 
  s + (a.question?.points || 0), 0)

// Kazanılan puan: (soru puanı * cevap çarpanı) toplamı
const earnedPoints = effectiveAnswers.reduce((s, a) => 
  s + ((a.question?.points || 0) * (SCORE_MAP[a.value] ?? 0)), 0)

// Yüzde
const percent = totalPoints ? Math.round((earnedPoints / totalPoints) * 100) : 0
```

### 8.2 Kategori Bazlı Döküm

Her kategori için ayrı ayrı:
- `categoryId`: Kategori ID
- `title`: Kategori başlığı
- `totalPoints`: Kategorideki toplam puan
- `earnedPoints`: Kategoriden kazanılan puan
- `percent`: Kategori başarı yüzdesi

### 8.3 Örnek Hesaplama

| Soru | Puan | Cevap | Çarpan | Kazanılan |
|------|------|-------|--------|-----------|
| S1 | 5 | U | 1 | 5 |
| S2 | 5 | UD | 0 | 0 |
| S3 | 5 | YP | 0.5 | 2.5 |
| S4 | 5 | DD | - | (dışarıda) |

**Hesaplama:**
- effectiveAnswers: S1, S2, S3 (3 soru)
- totalPoints: 15
- earnedPoints: 7.5
- percent: 50%

---

## 9. Kurulum Kılavuzu

### 9.1 Backend Kurulumu

```bash
# 1. Proje dizinine git
cd teftisistanBE

# 2. Bağımlılıkları yükle
npm install

# 3. Prisma client oluştur
npx prisma generate

# 4. Veritabanı migrasyonu
npx prisma migrate dev --name init

# 5. Sunucuyu başlat
npm run dev
# veya
node src/server.js
```

**Sunucu Portu:** 8080 (varsayılan)

### 9.2 Frontend Kurulumu

```bash
# 1. Proje dizinine git
cd teftisistanFE

# 2. Bağımlılıkları yükle
npm install

# 3. Geliştirme sunucusunu başlat
npm run dev
```

**Sunucu Portu:** 5173 (Vite varsayılan)

### 9.3 Ortam Değişkenleri

```env
# Backend
JWT_SECRET=change-me-in-env
PORT=8080
```

### 9.4 Varsayılan Kullanıcılar (Seed Data)

Aşağıdaki kullanıcıları veritabanına ekleyin:

| E-posta | Şifre | Rol |
|---------|-------|-----|
| admin@demo.local | Admin123! | admin |
| planlama@demo.local | Plan123! | planlamacı |
| saha@demo.local | Field123! | field |
| onay@demo.local | Onay123! | gözden_geçiren |
| firma@demo.local | Firma123! | firma_sahibi |

### 9.5 CORS Ayarları

Backend'de CORS tüm origin'lere açık:
```javascript
app.use(cors({ origin: true, credentials: true }))
```

### 9.6 Dosya Yükleme

Yüklenen dosyalar `/uploads` klasörüne kaydedilir ve `/uploads/<filename>` path'i ile erişilebilir.

---

## 📝 Ek Notlar

### Güvenlik Önlemleri
1. Helmet.js ile HTTP güvenlik header'ları
2. Rate limiting (200 istek/15 dakika, login için 20/10 dakika)
3. JWT token ile kimlik doğrulama
4. bcrypt ile şifre hashleme
5. Zod ile input validasyonu

### Responsive Tasarım
- Tüm sayfalar mobil uyumlu
- Sidebar mobilde hamburger menü ile açılır
- Grid layout büyük ekranlarda 3 kolon, mobilde 1 kolon

### Dark Mode
- Tüm sayfalarda dark mode desteği
- `class="dark"` ile aktif

### Tailwind Konfigürasyonu
Her sayfada inline Tailwind config ile özel renkler tanımlanmış:
- Primary: Yeşil tonları (#13ec5b)
- Background: Koyu yeşil (#102216)
- Surface: Koyu kartlar (#1a3323)

---

**Bu dokümantasyonu kullanarak TeftişPro uygulamasının birebir aynısını sıfırdan oluşturabilirsiniz.**
