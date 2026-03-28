// TeftişPro - Şirket Zod şemaları
// Faz 4.1

const { z } = require('zod');
const { paramsIdSchema } = require('./common');

const updateCompanySchema = z.object({
  body: z.object({
    name: z.string().min(1, 'Şirket adı gerekli').optional(),
    logoUrl: z.string().url().optional().nullable().or(z.literal('')),
    ownerId: z.number().int().positive().optional().nullable()
  }),
  params: paramsIdSchema
});

const deleteCompanySchema = z.object({
  params: paramsIdSchema
});

module.exports = {
  updateCompanySchema,
  deleteCompanySchema
};
