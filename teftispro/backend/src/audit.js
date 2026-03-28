// TeftişPro - Faz 5: Denetim İzi (Audit Trail)
// ISO 27001 Ek A 8.15, 8.16

const logger = require('./logger');

let prisma = null;

function init(prismaInstance) {
  prisma = prismaInstance;
}

const SENSITIVE_KEYS = [
  'password', 'token', 'secret', 'authorization', 'cookie',
  'creditCard', 'access_token', 'refresh_token', 'csrf_token'
];

/**
 * Hassas verileri loglardan maskele (PII sızıntı önleme)
 */
function sanitizeLogData(data) {
  if (!data || typeof data !== 'object') return data;
  const sanitized = { ...data };
  for (const key of Object.keys(sanitized)) {
    if (SENSITIVE_KEYS.some(sk => key.toLowerCase().includes(sk))) {
      sanitized[key] = '[REDACTED]';
    }
    if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
      sanitized[key] = sanitizeLogData(sanitized[key]);
    }
  }
  return sanitized;
}

/**
 * E-posta adresini kısmen maskele (örn: u***@example.com)
 */
function maskEmail(email) {
  if (!email || typeof email !== 'string') return null;
  const [local, domain] = email.split('@');
  if (!domain) return '***';
  const masked = local.length <= 2 ? '***' : local[0] + '***' + local[local.length - 1];
  return `${masked}@${domain}`;
}

/**
 * Denetim izi kaydı oluştur
 * @param {Object} opts
 * @param {string} [opts.userId]
 * @param {string} [opts.userEmail]
 * @param {string} opts.action - CREATE, UPDATE, DELETE, LOGIN, LOGIN_FAILED, LOGOUT, ACCESS_DENIED, RATE_LIMIT, CSRF_FAILED
 * @param {string} opts.resource - User, Audit, Company, Branch, Region, Category, Question, CorrectiveAction, Profile, File
 * @param {string|number} [opts.resourceId]
 * @param {Object} [opts.oldValue] - sanitize edilir
 * @param {Object} [opts.newValue] - sanitize edilir
 * @param {string} [opts.ipAddress]
 * @param {string} [opts.userAgent]
 * @param {string} [opts.details]
 */
async function createAuditLog(opts) {
  if (!prisma) return;
  try {
    const oldVal = opts.oldValue != null ? JSON.stringify(sanitizeLogData(opts.oldValue)) : null;
    const newVal = opts.newValue != null ? JSON.stringify(sanitizeLogData(opts.newValue)) : null;

    await prisma.auditLog.create({
      data: {
        userId: opts.userId ?? null,
        userEmail: opts.userEmail ?? null,
        action: opts.action,
        resource: opts.resource,
        resourceId: opts.resourceId != null ? String(opts.resourceId) : null,
        oldValue: oldVal,
        newValue: newVal,
        ipAddress: opts.ipAddress ?? null,
        userAgent: opts.userAgent ?? null,
        details: opts.details ?? null
      }
    });
  } catch (err) {
    logger.error('Audit log oluşturma hatası:', { error: err.message, action: opts.action, resource: opts.resource });
  }
}

module.exports = {
  init,
  createAuditLog,
  sanitizeLogData,
  maskEmail
};
