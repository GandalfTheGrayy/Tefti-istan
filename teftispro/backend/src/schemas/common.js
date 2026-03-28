// TeftişPro - Ortak Zod şemaları ve yardımcılar
// Faz 4.1: Merkezi validasyon

const { z } = require('zod');

function parseId(value) {
  const id = parseInt(value, 10);
  if (isNaN(id) || id <= 0) {
    throw new Error('Geçersiz ID');
  }
  return id;
}

// Faz 2.2: Şifre karmaşıklık politikası
const passwordSchema = z.string()
  .min(12, 'Şifre en az 12 karakter olmalı')
  .regex(/[A-Z]/, 'Şifre en az bir büyük harf içermeli')
  .regex(/[a-z]/, 'Şifre en az bir küçük harf içermeli')
  .regex(/[0-9]/, 'Şifre en az bir rakam içermeli')
  .regex(/[^A-Za-z0-9]/, 'Şifre en az bir özel karakter içermeli');

const paramsIdSchema = z.object({
  id: z.string().transform(v => parseId(v))
});

const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const paramsUuidSchema = z.object({
  id: z.string().regex(uuidRegex, 'Geçersiz UUID')
});

// Sadece params.id doğrulayan şema (GET/DELETE /:id endpoint'leri için)
const paramsOnlySchema = z.object({
  body: z.object({}).optional(),
  params: paramsIdSchema,
  query: z.object({}).optional()
});

module.exports = {
  parseId,
  passwordSchema,
  paramsIdSchema,
  paramsUuidSchema,
  paramsOnlySchema,
  z
};
