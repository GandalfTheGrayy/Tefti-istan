-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Audit" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "userId" INTEGER NOT NULL,
    "reviewerId" INTEGER,
    "assignedById" INTEGER,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "scheduledDate" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "deletedAt" DATETIME,
    "companyId" INTEGER,
    "branchId" INTEGER,
    "nextAuditDate" DATETIME,
    "title" TEXT,
    "authorizedPerson" TEXT,
    "clientSignatureUrl" TEXT,
    "auditorSignatureUrl" TEXT,
    "revisionNote" TEXT,
    CONSTRAINT "Audit_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Audit_reviewerId_fkey" FOREIGN KEY ("reviewerId") REFERENCES "User" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "Audit_companyId_fkey" FOREIGN KEY ("companyId") REFERENCES "Company" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "Audit_branchId_fkey" FOREIGN KEY ("branchId") REFERENCES "Branch" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_Audit" ("auditorSignatureUrl", "authorizedPerson", "branchId", "clientSignatureUrl", "companyId", "createdAt", "deletedAt", "id", "nextAuditDate", "reviewerId", "revisionNote", "status", "title", "updatedAt", "userId") SELECT "auditorSignatureUrl", "authorizedPerson", "branchId", "clientSignatureUrl", "companyId", "createdAt", "deletedAt", "id", "nextAuditDate", "reviewerId", "revisionNote", "status", "title", "updatedAt", "userId" FROM "Audit";
DROP TABLE "Audit";
ALTER TABLE "new_Audit" RENAME TO "Audit";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
