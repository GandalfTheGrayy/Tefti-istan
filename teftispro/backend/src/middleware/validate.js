// TeftişPro - Merkezi Zod validasyon middleware
// Faz 4.1

const { z } = require('zod');

function validate(schema) {
  return (req, res, next) => {
    try {
      req.validated = schema.parse({
        body: req.body || {},
        params: req.params || {},
        query: req.query || {}
      });
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Doğrulama hatası',
          details: error.errors.map(e => ({
            field: e.path.join('.'),
            message: e.message
          }))
        });
      }
      // Transform içinden gelen hatalar (parseId vb.)
      if (error.message === 'Geçersiz ID') {
        return res.status(400).json({
          error: 'Doğrulama hatası',
          details: [{ field: 'params.id', message: 'Geçersiz ID' }]
        });
      }
      next(error);
    }
  };
}

module.exports = { validate };
