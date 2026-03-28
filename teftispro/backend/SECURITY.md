# TeftişPro Backend — Güvenlik Notları

## SQL Injection Koruması (Faz 4.2)

Proje Prisma ORM kullanmaktadır. Parametreli sorgular otomatik uygulanır.

**Raw SQL kullanımı gerektiğinde:**
- `prisma.$queryRaw` (tagged template) kullanın — parametreler otomatik escape edilir
- `prisma.$queryRawUnsafe` **kullanmayın** — SQL injection riski

```javascript
// GÜVENLİ
const result = await prisma.$queryRaw`SELECT * FROM User WHERE email = ${email}`;

// GÜVENSİZ — KULLANMAYIN
const result = await prisma.$queryRawUnsafe(`SELECT * FROM User WHERE email = '${email}'`);
```
