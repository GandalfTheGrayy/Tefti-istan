// TeftişPro - Düzeltici Faaliyet Zod şemaları
// Faz 4.1

const { z } = require('zod');
const { paramsIdSchema, paramsUuidSchema } = require('./common');

const correctiveActionCreateSchema = z.object({
  body: z.object({
    auditId: z.string().uuid('Geçersiz denetim ID'),
    questionId: z.number({ required_error: 'Soru ID gerekli' }).int().positive(),
    description: z.string().min(1, 'Açıklama gerekli'),
    assignedTo: z.number().int().positive().optional().nullable(),
    dueDate: z.string().optional().nullable().or(z.literal(''))
  }),
  params: z.object({})
});

const correctiveActionUpdateSchema = z.object({
  body: z.object({
    status: z.enum(['open', 'in_progress', 'closed']).optional(),
    closedNote: z.string().optional()
  }),
  params: paramsIdSchema
});

const auditCorrectiveActionsSchema = z.object({
  body: z.object({
    actions: z.array(z.object({
      questionId: z.number().int().positive(),
      description: z.string().optional(),
      photoUrls: z.array(z.string()).optional()
    })).min(1, 'Aksiyon listesi boş olamaz')
  }),
  params: paramsUuidSchema
});

module.exports = {
  correctiveActionCreateSchema,
  correctiveActionUpdateSchema,
  auditCorrectiveActionsSchema
};
