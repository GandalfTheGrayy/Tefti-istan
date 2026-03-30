# TeftişPro — Teftiş ve Kalite Kontrol Uygulaması

## 📋 Genel Bakış

**TeftişPro**, şirketlerin şubelerinde yapılan denetimleri (teftiş) dijital ortamda planlayan, gerçekleştiren, raporlayan ve takip eden profesyonel bir **Teftiş & Kalite Kontrol** web uygulamasıdır.

Uygulama, denetim sürecinin başından sonuna kadar tüm adımlarını yönetir:

1. **Denetim Planlama** — Admin veya planlamacı, bir saha denetçisine denetim görevi atar
2. **Denetim Gerçekleştirme** — Saha denetçisi, sahada soruları yanıtlar, fotoğraf çeker, imza alır
3. **Gözden Geçirme** — Yetkili kişi denetimi onaylar veya revizyon talep eder
4. **Raporlama** — PDF raporları oluşturulur, uygunsuzluklar takip edilir
5. **Düzeltici Faaliyetler** — Şube kullanıcıları aksiyon bildirir, merkez takip eder

---

## 🏗️ Proje Yapısı

```
teftişistanv2/
├── .gitignore
├── teftispro/
│   ├── backend/                    # Express.js API sunucusu
│   │   ├── package.json
│   │   ├── prisma/
│   │   │   ├── schema.prisma       # Veritabanı şeması (12 model)
│   │   │   ├── seed.js             # Varsayılan veriler
│   │   │   ├── dev.db              # SQLite veritabanı dosyası
│   │   │   └── migrations/         # Prisma migration dosyaları
│   │   ├── src/
│   │   │   └── server.js           # Tüm API endpoint'leri (~1900 satır)
│   │   └── uploads/                # Yüklenen fotoğraf/imza dosyaları
│   │
│   └── frontend/                   # Vite tabanlı çok sayfalı frontend
│       ├── package.json
│       ├── vite.config.js          # Vite yapılandırması + proxy ayarları
│       ├── index.html              # Giriş noktası (yönlendirme)
│       └── public/
│           ├── styles.css          # Tasarım sistemi (1047 satır CSS)
│           ├── layout.js           # Paylaşılan sidebar, header, tema yönetimi
│           ├── login.html          # Giriş sayfası
│           ├── kontrol_paneli.html # Dashboard / Ana panel
│           ├── denetim_listesi.html# Denetim listesi
│           ├── denetim_cevaplama.html # Denetim cevaplama formu
│           ├── denetim_inceleme.html  # Denetim detay inceleme
│           ├── raporlar.html       # Raporlar sayfası
│           ├── sirket_yonetimi.html# Şirket CRUD yönetimi
│           ├── bolge_yonetimi.html # Bölge CRUD yönetimi
│           ├── sube_yonetimi.html  # Şube CRUD yönetimi
│           ├── kategori_yonetimi.html # Kategori & soru yönetimi
│           ├── admin_yonetimi.html # Kullanıcı yönetimi
│           ├── profil.html         # Profil & şifre değiştirme
│           └── assets/             # Logo ve statik dosyalar
```

---

## 🛠️ Kullanılan Teknolojiler

### Backend

| Teknoloji | Versiyon | Açıklama |
|-----------|----------|----------|
| **Node.js** | — | JavaScript çalışma ortamı |
| **Express.js** | ^4.21.1 | HTTP sunucu framework'ü. Tüm API endpoint'leri burada tanımlı |
| **Prisma ORM** | ^5.22.0 | Veritabanı erişim katmanı. `schema.prisma` ile model tanımlama, migration, seed desteği |
| **SQLite** | — | Gömülü veritabanı (`prisma/dev.db`). Kurulum gerektirmez |
| **bcryptjs** | ^2.4.3 | Şifre hashleme (10 round salt) |
| **jsonwebtoken (JWT)** | ^9.0.2 | Token tabanlı kimlik doğrulama. 24 saat geçerlilik |
| **multer** | ^1.4.5 | Dosya yükleme (fotoğraf, imza). Maks. 10MB limit |
| **helmet** | ^8.0.0 | HTTP güvenlik başlıkları (XSS, clickjacking koruması) |
| **cors** | ^2.8.5 | Cross-Origin Resource Sharing desteği |
| **morgan** | ^1.10.0 | HTTP istek loglama (geliştirme ortamı) |
| **express-rate-limit** | ^7.4.0 | Brute-force koruması. Genel: 200/15dk, Login: 20/10dk |
| **zod** | ^3.23.8 | Çalışma zamanı veri doğrulama (input validation) |
| **pdfkit** | ^0.17.2 | Sunucu tarafında PDF rapor oluşturma |

### Frontend

| Teknoloji | Versiyon | Açıklama |
|-----------|----------|----------|
| **Vite** | ^5.4.0 | Geliştirme sunucusu ve build aracı |
| **Vanilla HTML/CSS/JS** | — | Framework kullanılmadan saf web teknolojileri |
| **TailwindCSS** | CDN | Utility-first CSS sınıfları (CDN üzerinden) |
| **Material Symbols** | CDN | Google Material Design ikon seti |
| **Inter Font** | CDN | Modern tipografi (Google Fonts) |
| **jsPDF** | ^4.0.0 | İstemci tarafında PDF oluşturma |

### Geliştirme Araçları

| Araç | Açıklama |
|------|----------|
| **Git** | Versiyon kontrolü |
| **Prisma CLI** | Migration, seed, studio komutları |
| **Vite Dev Server** | Hot reload, proxy yapılandırması |

---

## 🗄️ Veritabanı Şeması

Uygulama **12 model** içerir. Aşağıda her model ve alanları detaylı açıklanmıştır:

### 1. Role (Rol)

Kullanıcı rollerini tanımlar. Sistemde 6 adet rol bulunur.

| Alan | Tip | Açıklama |
|------|-----|----------|
| `id` | Int (PK) | Otomatik artan |
| `name` | String (unique) | `admin`, `planlamacı`, `field`, `gözden_geçiren`, `firma_sahibi`, `sube_kullanici` |

### 2. User (Kullanıcı)

| Alan | Tip | Açıklama |
|------|-----|----------|
| `id` | Int (PK) | Otomatik artan |
| `email` | String (unique) | E-posta adresi (giriş için kullanılır) |
| `password` | String | bcrypt ile hashlenmiş şifre |
| `roleId` | Int (FK → Role) | Kullanıcının rolü |
| `profilePhoto` | String? | Profil fotoğrafı URL'si |
| `signatureUrl` | String? | Önceden tanımlı imza URL'si |
| `companyId` | Int? | Bağlı olduğu şirket ID'si |
| `branchId` | Int? | Bağlı olduğu şube ID'si |
| `createdAt` | DateTime | Oluşturulma tarihi |

**İlişkiler:** Denetimler (auditor/reviewer olarak), şube atamaları, sahip olunan şirketler, bildirimler.

### 3. Company (Şirket)

| Alan | Tip | Açıklama |
|------|-----|----------|
| `id` | Int (PK) | Otomatik artan |
| `name` | String (unique) | Şirket adı |
| `logoUrl` | String? | Logo URL'si |
| `ownerId` | Int? (FK → User) | Firma sahibi kullanıcı |
| `createdAt` | DateTime | Oluşturulma tarihi |

**İlişkiler:** Şubeler, bölgeler, denetimler, şirkete özel sorular.

### 4. Region (Bölge)

Şubeleri coğrafi bölgelere ayırmak için kullanılır.

| Alan | Tip | Açıklama |
|------|-----|----------|
| `id` | Int (PK) | Otomatik artan |
| `name` | String | Bölge adı (şirket bazında unique) |
| `companyId` | Int (FK → Company) | Hangi şirkete ait |

### 5. Branch (Şube)

| Alan | Tip | Açıklama |
|------|-----|----------|
| `id` | Int (PK) | Otomatik artan |
| `name` | String | Şube adı |
| `city` | String | Şehir |
| `address` | String? | Adres |
| `phone` | String? | Telefon |
| `email` | String? | E-posta |
| `isActive` | Boolean | Aktif mi? (varsayılan: true) |
| `companyId` | Int (FK → Company) | Bağlı olduğu şirket |
| `regionId` | Int? (FK → Region) | Bağlı olduğu bölge |
| `createdAt` | DateTime | Oluşturulma tarihi |

### 6. Category (Kategori)

Denetim sorularını gruplandırmak için kullanılır.

| Alan | Tip | Açıklama |
|------|-----|----------|
| `id` | Int (PK) | Otomatik artan |
| `title` | String (unique) | Kategori adı (ör: "Genel Temizlik", "Yangın Güvenliği") |
| `createdAt` | DateTime | Oluşturulma tarihi |

### 7. Question (Soru)

| Alan | Tip | Açıklama |
|------|-----|----------|
| `id` | Int (PK) | Otomatik artan |
| `text` | String | Soru metni |
| `description` | String? | Detaylı açıklama |
| `points` | Int | Puan değeri (varsayılan: 5) |
| `noteRequired` | Boolean | Açıklama/not zorunlu mu? |
| `imageUrl` | String? | Soru görseli |
| `categoryId` | Int (FK → Category) | Hangi kategoriye ait |
| `companyId` | Int? (FK → Company) | null ise genel soru, değilse şirkete özel |
| `parentQuestionId` | Int? | Koşullu soru bağlantısı (üst soru) |
| `triggerValue` | String? | Hangi cevap değerinde alt soru gösterilsin (`U`, `UD`, `YP`) |

### 8. Audit (Denetim)

Uygulamanın ana modeli. Tüm denetim sürecini yönetir.

| Alan | Tip | Açıklama |
|------|-----|----------|
| `id` | Int (PK) | Otomatik artan |
| `userId` | Int (FK → User) | Atanan denetçi |
| `reviewerId` | Int? (FK → User) | Onaylayan kişi |
| `assignedById` | Int? | Atayan kişi (planlamacı/admin) |
| `status` | String | Durum: `pending`, `draft`, `submitted`, `approved`, `rejected`, `revision_requested` |
| `scheduledDate` | DateTime? | Planlanan denetim tarihi |
| `title` | String? | Denetim başlığı |
| `authorizedPerson` | String? | Yetkili kişi adı |
| `clientSignatureUrl` | String? | Karşı taraf imza URL |
| `auditorSignatureUrl` | String? | Denetçi imza URL |
| `revisionNote` | String? | Revizyon talebi notu |
| `latitude` / `longitude` | Float? | GPS konum bilgisi |
| `nextAuditDate` | DateTime? | Sonraki denetim tarihi |
| `deletedAt` | DateTime? | Soft delete tarihi |
| `createdAt` / `updatedAt` | DateTime | Zaman damgaları |

### 9. Answer (Cevap)

Her soruya verilen cevabı saklar.

| Alan | Tip | Açıklama |
|------|-----|----------|
| `id` | Int (PK) | Otomatik artan |
| `auditId` | Int (FK → Audit) | Hangi denetime ait |
| `questionId` | Int (FK → Question) | Hangi soruya ait |
| `value` | String | `U` (Uygun), `YP` (Yarı Puanlı), `UD` (Uygun Değil), `DD` (Değerlendirme Dışı) |
| `note` | String? | Açıklama/not |

**Kısıtlama:** `(auditId, questionId)` çifti benzersiz (unique) olmalıdır.

### 10. Photo (Fotoğraf)

| Alan | Tip | Açıklama |
|------|-----|----------|
| `id` | Int (PK) | Otomatik artan |
| `auditId` | Int (FK → Audit) | Hangi denetime ait |
| `questionId` | Int? | Hangi soruya ait (null ise genel fotoğraf) |
| `url` | String | Dosya yolu |
| `latitude` / `longitude` | Float? | GPS konum |

### 11. Notification (Bildirim)

| Alan | Tip | Açıklama |
|------|-----|----------|
| `id` | Int (PK) | Otomatik artan |
| `userId` | Int (FK → User) | Hedef kullanıcı |
| `title` | String | Bildirim başlığı |
| `message` | String | Bildirim mesajı |
| `type` | String | `audit_assigned`, `audit_approved`, `audit_rejected`, `audit_submitted`, `corrective_action` |
| `read` | Boolean | Okundu mu? |
| `auditId` | Int? | İlgili denetim ID |

### 12. CorrectiveAction (Düzeltici Faaliyet)

Uygunsuz bulguların takibi ve çözümlenmesi için kullanılır.

| Alan | Tip | Açıklama |
|------|-----|----------|
| `id` | Int (PK) | Otomatik artan |
| `auditId` | Int (FK → Audit) | Hangi denetime ait |
| `questionId` | Int (FK → Question) | Hangi soruya ait |
| `description` | String | Açıklama |
| `assignedTo` | Int? | Sorumlu kişi ID |
| `dueDate` | DateTime? | Termin tarihi |
| `status` | String | `open`, `in_progress`, `closed` |
| `closedAt` | DateTime? | Kapatılma tarihi |
| `closedNote` | String? | Kapanış notu |

### 13. BranchAssignment (Şube Ataması)

Hangi denetçinin hangi şubeye atandığını tanımlar.

| Alan | Tip | Açıklama |
|------|-----|----------|
| `branchId` | Int (FK → Branch) | Şube |
| `userId` | Int (FK → User) | Denetçi |

---

## 🔐 Kimlik Doğrulama & Yetkilendirme

### JWT Token Sistemi

- Giriş yaparken JWT token üretilir (24 saat geçerli)
- Token payload'ı: `{ id, email, role }`
- Her korumalı endpoint'e `Authorization: Bearer <token>` header'ı ile erişilir
- Token localStorage'da `token` anahtarıyla saklanır

### Rol Tabanlı Erişim Kontrolü (RBAC)

Sistemde **6 rol** vardır. Her rolün erişebildiği sayfalar ve yapabildiği işlemler farklıdır:

| Rol | Türkçe Adı | Yetkiler |
|-----|------------|----------|
| `admin` | Yönetici | **Tam yetki.** Şirket, şube, bölge, kullanıcı, kategori, soru CRUD. Denetim oluşturma, onaylama, silme. Tüm verilere erişim. |
| `planlamacı` | Planlamacı | Denetim oluşturma ve denetçiye atama. Kategori & soru yönetimi. Denetim onaylama/reddetme. |
| `field` | Saha Denetçisi | Sadece kendine atanan denetimleri görür. Denetim başlatma, cevaplama, fotoğraf/imza ekleme, gönderme. |
| `gözden_geçiren` | Gözden Geçiren | Denetimleri onaylama veya revizyon talep etme. Raporları görüntüleme. |
| `firma_sahibi` | Firma Sahibi | Sadece kendi şirketinin denetimlerini ve raporlarını görür. Düzeltici faaliyet takibi. |
| `sube_kullanici` | Şube Kullanıcı | Sadece kendi şubesinin denetimlerini görür. Aksiyon bildirimi gönderebilir. |

### Erişim Kısıtlamaları

- **Şirket verisi:** Firma sahibi yalnızca kendi şirketini görür
- **Şube verisi:** Field kullanıcı sadece atandığı şubeleri, şube kullanıcı sadece kendi şubesini görür
- **Denetim verisi:** Her rol sadece ilgili denetimlere erişir (field → kendi denetimleri, firma_sahibi → kendi şirketinin denetimleri)

---

## 🌐 API Endpoint'leri

Backend, `http://localhost:3636` portunda çalışır. Frontend proxy ile `/api` prefix'i üzerinden erişir.

### Kimlik Doğrulama (Auth)

| Metod | Endpoint | Açıklama | Yetki |
|-------|----------|----------|-------|
| `POST` | `/auth/login` | E-posta ve şifre ile giriş, JWT token döner | Herkese açık |
| `GET` | `/auth/me` | Mevcut kullanıcı bilgisi | Giriş yapmış |

### Kullanıcı Yönetimi

| Metod | Endpoint | Açıklama | Yetki |
|-------|----------|----------|-------|
| `GET` | `/users` | Kullanıcı listesi (role filtresi destekler) | admin, planlamacı |
| `POST` | `/users` | Yeni kullanıcı oluşturma | admin |
| `DELETE` | `/users/:id` | Kullanıcı silme | admin |

### Şirket Yönetimi

| Metod | Endpoint | Açıklama | Yetki |
|-------|----------|----------|-------|
| `GET` | `/companies` | Şirket listesi | admin, planlamacı, firma_sahibi |
| `POST` | `/companies` | Yeni şirket oluşturma | admin |
| `PUT` | `/companies/:id` | Şirket güncelleme | admin |
| `DELETE` | `/companies/:id` | Şirket silme | admin |

### Bölge Yönetimi

| Metod | Endpoint | Açıklama | Yetki |
|-------|----------|----------|-------|
| `GET` | `/regions` | Bölge listesi (companyId filtresi) | admin, planlamacı |
| `POST` | `/regions` | Yeni bölge oluşturma | admin |
| `DELETE` | `/regions/:id` | Bölge silme | admin |

### Şube Yönetimi

| Metod | Endpoint | Açıklama | Yetki |
|-------|----------|----------|-------|
| `GET` | `/branches` | Şube listesi (rol bazlı filtreleme) | Giriş yapmış |
| `POST` | `/branches` | Yeni şube oluşturma | admin |
| `PUT` | `/branches/:id` | Şube güncelleme | admin |
| `DELETE` | `/branches/:id` | Şube silme | admin |
| `POST` | `/branches/:id/assign` | Denetçi atama | admin, planlamacı |

### Kategori & Soru Yönetimi

| Metod | Endpoint | Açıklama | Yetki |
|-------|----------|----------|-------|
| `GET` | `/categories` | Kategori listesi (sorularla birlikte) | Giriş yapmış |
| `POST` | `/categories` | Yeni kategori | admin |
| `DELETE` | `/categories/:id` | Kategori silme | admin |
| `POST` | `/questions` | Yeni soru oluşturma | admin |
| `DELETE` | `/questions/:id` | Soru silme | admin |

### Denetim Yönetimi

| Metod | Endpoint | Açıklama | Yetki |
|-------|----------|----------|-------|
| `GET` | `/audits` | Denetim listesi (rol bazlı filtreleme) | Giriş yapmış |
| `GET` | `/audits/:id` | Denetim detayı | Giriş yapmış (erişim kısıtlı) |
| `POST` | `/audits` | Yeni denetim oluşturma & atama | admin, planlamacı |
| `POST` | `/audits/:id/start` | Denetimi başlatma (pending → draft) | field |
| `POST` | `/audits/:id/answers` | Cevapları kaydetme (upsert) | Denetim sahibi |
| `POST` | `/audits/:id/photos` | Fotoğraf yükleme | Denetim sahibi |
| `POST` | `/audits/:id/signature` | İmza kaydetme (base64) | Denetim sahibi |
| `POST` | `/audits/:id/signatures` | Çift imza yükleme (FormData) | Denetim sahibi |
| `POST` | `/audits/:id/submit` | Denetimi gönderme (draft → submitted) | Denetim sahibi |
| `POST` | `/audits/:id/review` | Onaylama/reddetme | admin, gözden_geçiren, planlamacı |
| `DELETE` | `/audits/:id` | Soft delete | admin |
| `POST` | `/audits/:id/corrective-actions` | Şube aksiyon bildirimi | sube_kullanici, admin |

### PDF Raporları

| Metod | Endpoint | Açıklama | Yetki |
|-------|----------|----------|-------|
| `GET` | `/audits/:id/pdf` | Genel denetim raporu PDF | Giriş yapmış (erişim kısıtlı) |
| `GET` | `/audits/:id/pdf-nonconformity` | Uygunsuzluk raporu PDF (sadece UD cevaplar) | Giriş yapmış (erişim kısıtlı) |

### İstatistikler

| Metod | Endpoint | Açıklama | Yetki |
|-------|----------|----------|-------|
| `GET` | `/stats/overview` | Dashboard özet istatistikleri | Giriş yapmış |
| `GET` | `/stats/annual` | 12 aylık grafik verisi | Giriş yapmış |
| `GET` | `/stats/branch/:id` | Şube bazlı detaylı istatistikler | Giriş yapmış (erişim kısıtlı) |

### Bildirimler

| Metod | Endpoint | Açıklama | Yetki |
|-------|----------|----------|-------|
| `GET` | `/notifications` | Kullanıcının bildirimleri (son 50) | Giriş yapmış |
| `POST` | `/notifications/:id/read` | Bildirimi okundu işaretle | Giriş yapmış |
| `POST` | `/notifications/read-all` | Tüm bildirimleri okundu işaretle | Giriş yapmış |

### Düzeltici Faaliyetler

| Metod | Endpoint | Açıklama | Yetki |
|-------|----------|----------|-------|
| `GET` | `/corrective-actions` | Düzeltici faaliyet listesi | Giriş yapmış |
| `POST` | `/corrective-actions` | Yeni düzeltici faaliyet | admin, planlamacı, gözden_geçiren |
| `PUT` | `/corrective-actions/:id` | Faaliyet güncelleme/kapatma | Yetkili roller + atanan kişi |

### Profil & Dosya

| Metod | Endpoint | Açıklama | Yetki |
|-------|----------|----------|-------|
| `PUT` | `/profile` | Profil güncelleme (fotoğraf, imza) | Giriş yapmış |
| `PUT` | `/profile/password` | Şifre değiştirme | Giriş yapmış |
| `POST` | `/upload` | Genel dosya yükleme | Giriş yapmış |

---

## 📱 Frontend Sayfaları

### Ortak Bileşenler

#### `layout.js` — Paylaşılan Layout Sistemi
- **Sidebar:** Rol bazlı menü oluşturma. Her rol sadece yetkili olduğu menüleri görür
- **Header:** Sayfa başlığı, breadcrumb, tema değiştirme, bildirim butonu, profil avatarı
- **Tema Yönetimi:** Light/Dark mod desteği. `localStorage` ile kalıcılık. Sistem tercihini algılama
- **Palet Yönetimi:** İki renk paleti: Emerald (yeşil, varsayılan) ve Corporate (amber/turuncu)
- **Toast Bildirimler:** Sağ üst köşede anlık bildirimler (success, error, warning, info)
- **Responsive:** Mobilde hamburger menü, masaüstünde sabit sidebar

#### `styles.css` — Tasarım Sistemi (Design System)
- **CSS Değişkenleri:** 30+ adet CSS custom property (renk, gölge, arkaplan, border)
- **Dark Mode:** `[data-theme="dark"]` seçicisi ile tam karanlık mod desteği
- **Bileşen Stilleri:**
  - `.tp-card` — Kart bileşeni (hover animasyonlu)
  - `.tp-btn`, `.tp-btn-primary`, `.tp-btn-secondary`, `.tp-btn-danger`, `.tp-btn-ghost` — Buton varyasyonları
  - `.tp-input`, `.tp-select`, `.tp-textarea` — Form elemanları
  - `.tp-badge-*` — Durum rozetleri (draft, pending, submitted, approved, rejected, revision_requested)
  - `.tp-role-*` — Rol rozetleri (admin, field, planlamacı, gözden_geçiren, firma_sahibi, sube_kullanici)
  - `.tp-modal-overlay`, `.tp-modal` — Modal pencereler (blur backdrop, slide-in animasyon)
  - `.tp-table` — Tablo stilleri (hover efekti)
  - `.tp-toast` — Bildirim toast'ları
  - `.answer-U`, `.answer-YP`, `.answer-UD`, `.answer-DD` — Cevap butonları (renk kodlu)
  - `.tp-stat-card` — İstatistik kartları (hover animasyonlu)
  - `.tp-progress-bar` — İlerleme çubuğu
  - `.tp-spinner` — Yükleme animasyonu
- **Animasyonlar:** `fadeIn`, `modalSlideIn`, `toastSlideIn/Out`, `floating`, `spin`

### Sayfa Detayları

| Sayfa | Dosya | Erişim Rolleri | İşlev |
|-------|-------|----------------|-------|
| **Giriş** | `login.html` | Herkese açık | E-posta/şifre ile giriş. JWT token alır ve localStorage'a kaydeder |
| **Kontrol Paneli** | `kontrol_paneli.html` | Tüm roller | Dashboard. İstatistik kartları, yıllık grafik, son denetimler tablosu |
| **Denetim Listesi** | `denetim_listesi.html` | Tüm roller | Tüm denetimlerin filtrelenebilir listesi. Durum filtreleri, arama, Excel export. Rol bazlı aksiyon butonları (görüntüle, düzenle, PDF, sil, uygunsuzluk bildir, aksiyon al) |
| **Denetim Cevaplama** | `denetim_cevaplama.html` | field, admin | Kategorilere göre soruları listeler. Her soru için U/YP/UD/DD cevap butonları, not alanı, fotoğraf yükleme. İmza padi, otomatik kaydetme |
| **Denetim İnceleme** | `denetim_inceleme.html` | Tüm roller | Denetim detayı: puan özeti, kategori dağılımı, her sorunun cevabı/notu/fotoğrafı, imzalar. Onaylama/reddetme butonları |
| **Raporlar** | `raporlar.html` | admin, planlamacı, gözden_geçiren, firma_sahibi | Detaylı raporlar: şube bazlı performans, denetçi karşılaştırma, zaman serisi grafikleri |
| **Şirket Yönetimi** | `sirket_yonetimi.html` | admin | Şirket ekleme, düzenleme, silme. Firma sahibi atama |
| **Bölge Yönetimi** | `bolge_yonetimi.html` | admin | Bölge ekleme/silme. Şirkete bağlı bölge tanımlama |
| **Şube Yönetimi** | `sube_yonetimi.html` | admin | Şube CRUD. Bölge ataması, denetçi ataması, iletişim bilgileri |
| **Kategori Yönetimi** | `kategori_yonetimi.html` | admin, planlamacı | Denetim kategorisi ve soruları ekleme/silme. Puan değeri belirleme |
| **Kullanıcılar** | `admin_yonetimi.html` | admin | Kullanıcı oluşturma, rol atama, şirket/şube bağlama, silme |
| **Profil** | `profil.html` | Tüm roller | Profil fotoğrafı, imza yükleme, şifre değiştirme |

---

## 🔄 Denetim Yaşam Döngüsü (Audit Lifecycle)

Denetimler şu durum akışını takip eder:

```
┌──────────┐     ┌──────────┐     ┌───────────┐     ┌───────────┐
│ pending  │────▶│  draft   │────▶│ submitted │────▶│ approved  │
│ (Atandı) │     │(Başlatıldı)    │ (Gönderildi)    │(Onaylandı)│
└──────────┘     └──────────┘     └───────────┘     └───────────┘
                       ▲                 │
                       │                 ▼
                       │          ┌──────────────────┐
                       └──────────│revision_requested│
                                  │(Revizyon İstendi) │
                                  └──────────────────┘
```

1. **`pending`** — Admin/planlamacı denetim oluşturur ve bir saha denetçisine (field) atar. Denetçiye bildirim gönderilir.
2. **`draft`** — Denetçi "Başlat" butonuna basar. Soruları cevaplayabilir, fotoğraf çekebilir, not ekleyebilir.
3. **`submitted`** — Denetçi tüm soruları cevapladıktan sonra denetimi gönderir. İmzalar eklenir.
4. **`approved`** — Gözden geçiren veya admin denetimi onaylar.
5. **`revision_requested`** — Gözden geçiren revizyon talep eder (not ile). Denetçi düzenleme yapabilir ve tekrar gönderebilir.

### Puan Hesaplama

Her cevap değerinin bir çarpanı vardır:

| Cevap | Açıklama | Çarpan |
|-------|----------|--------|
| **U** | Uygun | 1.0 (tam puan) |
| **YP** | Yarı Puanlı | 0.5 (yarım puan) |
| **UD** | Uygun Değil | 0.0 (sıfır puan) |
| **DD** | Değerlendirme Dışı | Hesaplamaya dahil edilmez |

**Formül:** `Yüzde = (Kazanılan Puan / Toplam Puan) × 100`

Puanlar hem genel hem de kategori bazlı hesaplanır.

---

## 📊 Bildirim Sistemi

Sistem otomatik bildirimler üretir:

| Olay | Bildirim Tipi | Kime Gider |
|------|---------------|------------|
| Denetim atandığında | `audit_assigned` | Atanan denetçiye |
| Aksiyon bildirimi gönderildiğinde | `corrective_action` | Denetçi, admin, planlamacı, gözden_geçiren, firma sahibi |
| Düzeltici faaliyet atandığında | `action_assigned` | Sorumlu kişiye |

---

## 📄 PDF Rapor Türleri

### 1. Genel Denetim Raporu (`/audits/:id/pdf`)
- Şirket, şube, denetçi, tarih bilgileri
- Toplam puan yüzdesi
- Kategorilere göre gruplandırılmış sorular ve cevapları
- Not alanları
- İmza alanları

### 2. Uygunsuzluk Raporu (`/audits/:id/pdf-nonconformity`)
- Sadece "Uygun Değil" (UD) cevaplarını içerir
- Uygunsuzluk sayısı
- Her uygunsuzluğun detayı: soru metni, kategori, açıklama

---

## ⚙️ Güvenlik Önlemleri

| Önlem | Detay |
|-------|-------|
| **Şifre Hashleme** | bcrypt (10 round salt) |
| **JWT Token** | 24 saat geçerlilik, gizli anahtar ile imzalı |
| **Rate Limiting** | Genel: 200 istek/15 dk, Login: 20 istek/10 dk |
| **Helmet** | XSS, clickjacking, MIME-type sniffing koruması |
| **CORS** | Credentials destekli cross-origin erişim |
| **Zod Validation** | Tüm input verileri şema bazlı doğrulanır |
| **Dosya Boyut Limiti** | Maksimum 10MB dosya yükleme |
| **Soft Delete** | Denetimler kalıcı olarak silinmez, `deletedAt` ile işaretlenir |
| **Rol Bazlı Erişim** | Her endpoint için yetkili roller tanımlı |

---

## 🚀 Kurulum & Çalıştırma

### Gereksinimler

- **Node.js** v18+
- **npm** v9+

### 1. Backend Kurulumu

```bash
cd teftispro/backend

# Bağımlılıkları yükle
npm install

# Prisma veritabanını oluştur ve migrate et
npx prisma migrate dev

# Varsayılan verileri ekle (kullanıcılar, kategoriler, sorular)
npm run seed

# Sunucuyu başlat (port 3636)
npm run dev
```

### 2. Frontend Kurulumu

```bash
cd teftispro/frontend

# Bağımlılıkları yükle
npm install

# Geliştirme sunucusunu başlat (port 2525)
npm run dev
```

### 3. Uygulamaya Erişim

- **Frontend:** `http://localhost:2525`
- **Backend API:** `http://localhost:3636`

Frontend, Vite proxy ayarı ile `/api` isteklerini otomatik olarak backend'e yönlendirir.

---

## 👤 Varsayılan Kullanıcılar (Seed)

| E-posta | Şifre | Rol |
|---------|-------|-----|
| `admin@demo.local` | `Admin123!` | Yönetici (admin) |
| `planlama@demo.local` | `Plan123!` | Planlamacı |
| `saha@demo.local` | `Field123!` | Saha Denetçisi (field) |
| `onay@demo.local` | `Onay123!` | Gözden Geçiren |
| `firma@demo.local` | `Firma123!` | Firma Sahibi (Demo Holding) |
| `firma@hdiskender.local` | `Firma123!` | Firma Sahibi (HD İskender) |
| `sube@hdiskender.local` | `Sube123!` | Şube Kullanıcı (HD İskender) |

### Varsayılan Veriler

- **2 Şirket:** Demo Holding A.Ş., HD İskender
- **2 Bölge:** Marmara Bölgesi, İstanbul Bölgesi
- **4 Şube:** Kadıköy, Beşiktaş, Bursa Merkez (Demo Holding), HD İskender Şube
- **5 Kategori:** Genel Temizlik, Yangın Güvenliği, İş Sağlığı ve Güvenliği, Müşteri Deneyimi, Depo ve Stok Yönetimi
- **25 Soru:** Her kategoride 5 adet soru (farklı puan değerlerinde)

---

## 🔧 Vite Yapılandırması

```javascript
// vite.config.js temel ayarlar
{
  server: {
    port: 2525,         // Frontend dev portu
    host: '0.0.0.0',    // Ağ üzerinden erişim
    proxy: {
      '/api': {
        target: 'http://localhost:3636',  // Backend'e yönlendirme
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, '')
      },
      '/uploads': {
        target: 'http://localhost:3636',  // Yüklenen dosyalar
        changeOrigin: true
      }
    }
  }
}
```

---

## 📁 Prisma Migration Geçmişi

| Migration | Açıklama |
|-----------|----------|
| `20260131234958_init` | İlk veritabanı şeması (temel modeller) |
| `20260201000224_add_scheduling` | Denetim planlama alanları eklendi |
| `20260201000652_add_notifications_actions` | Bildirim ve düzeltici faaliyet modelleri eklendi |
| `20260201174204_add_company_questions` | Şirkete özel soru desteği eklendi |

---

## 🎨 Tema & Renk Sistemi

### Light Mode
- Arkaplan: `#f8fafc` (açık gri)
- Kart: `#ffffff` (beyaz)
- Metin: `#0f172a` (koyu lacivert)
- Accent: `#10b981` (emerald yeşil)

### Dark Mode
- Arkaplan: `#0f172a` (koyu lacivert)
- Kart: `#1e293b` (koyu mavi-gri)
- Metin: `#f1f5f9` (açık gri)
- Accent: `#10b981` (emerald yeşil)

### Corporate Palet
- Accent renk `#d97706` (amber/turuncu) olarak değişir
- Tüm accent renkler amber tonlarına dönüşür

---

## 📝 Önemli Notlar

1. **Veritabanı:** SQLite gömülü veritabanı kullanılır. Dosya: `prisma/dev.db`. Production için PostgreSQL veya MySQL'e geçiş yapılabilir (sadece `schema.prisma`'daki `provider` değişir).

2. **Dosya Yükleme:** Fotoğraflar ve imzalar `backend/uploads/` klasörüne kaydedilir. Bu klasör `.gitignore`'da veritabanı ile birlikte görmezden gelinir.

3. **JWT Secret:** Varsayılan olarak sabit bir secret key kullanılır (`teftispro-super-secret-key-2024`). Production'da `JWT_SECRET` env değişkeni kullanılmalıdır.

4. **Soft Delete:** Denetimler kalıcı olarak silinmez, `deletedAt` alanı ile işaretlenir. Listeleme sorgularında `deletedAt: null` filtresi uygulanır.

5. **Responsive Tasarım:** Uygulama mobil uyumludur. Sidebar mobilde gizlenir, hamburger menü ile açılır. Tüm sayfalar responsive layout kullanır.

6. **Koşullu Sorular:** Sorular hiyerarşik olabilir. Bir sorunun cevabına göre alt sorular gösterilebilir (`parentQuestionId`, `triggerValue` alanları).
