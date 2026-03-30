// TeftişPro - Profil Zod şemaları
// Faz 4.1

const { z } = require('zod');

const profileUpdateSchema = z.object({
  body: z.object({
    profilePhoto: z.string().url().optional().nullable().or(z.literal('')),
    signatureUrl: z.string().url().optional().nullable().or(z.literal(''))
  })
});

const profileSignatureSchema = z.object({
  body: z.object({
    dataUrl: z.string().min(1, 'dataUrl gerekli')
  })
});

module.exports = {
  profileUpdateSchema,
  profileSignatureSchema
};
