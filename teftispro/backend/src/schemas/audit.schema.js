// TeftişPro - Denetim Zod şemaları
// Faz 4.1

const { z } = require('zod');
const { paramsUuidSchema } = require('./common');

const auditParamsSchema = z.object({
  params: paramsUuidSchema
});

const auditAnswersSchema = z.object({
  body: z.object({
    items: z.array(z.object({
      questionId: z.number().int().positive(),
      value: z.enum(['U', 'YP', 'UD', 'DD']),
      note: z.string().optional().nullable()
    })).min(1, 'En az bir cevap gerekli')
  }),
  params: paramsUuidSchema
});

const auditReviewSchema = z.object({
  body: z.object({
    action: z.enum(['approve', 'reject'], { required_error: 'action (approve/reject) gerekli' }),
    note: z.string().optional()
  }),
  params: paramsUuidSchema
});

module.exports = {
  auditParamsSchema,
  auditAnswersSchema,
  auditReviewSchema
};
