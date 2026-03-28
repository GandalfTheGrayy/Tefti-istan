// TeftişPro - Şube Zod şemaları
// Faz 4.1

const { z } = require('zod');
const { paramsIdSchema } = require('./common');

const updateBranchSchema = z.object({
  body: z.object({
    name: z.string().min(1).optional(),
    city: z.string().min(1).optional(),
    address: z.string().optional(),
    phone: z.string().optional(),
    email: z.string().email().optional().or(z.literal('')),
    regionId: z.number().int().positive().optional().nullable(),
    isActive: z.boolean().optional()
  }),
  params: paramsIdSchema
});

const assignBranchSchema = z.object({
  body: z.object({
    userId: z.string({ required_error: 'Kullanıcı ID gerekli' }).uuid('Geçerli UUID gerekli')
  }),
  params: paramsIdSchema
});

module.exports = {
  updateBranchSchema,
  assignBranchSchema
};
