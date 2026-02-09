-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Question" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "text" TEXT NOT NULL,
    "description" TEXT,
    "points" INTEGER NOT NULL DEFAULT 5,
    "noteRequired" BOOLEAN NOT NULL DEFAULT false,
    "imageUrl" TEXT,
    "categoryId" INTEGER NOT NULL,
    "companyId" INTEGER,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "parentQuestionId" INTEGER,
    "triggerValue" TEXT,
    CONSTRAINT "Question_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "Category" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "Question_companyId_fkey" FOREIGN KEY ("companyId") REFERENCES "Company" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "Question_parentQuestionId_fkey" FOREIGN KEY ("parentQuestionId") REFERENCES "Question" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_Question" ("categoryId", "createdAt", "description", "id", "imageUrl", "noteRequired", "parentQuestionId", "points", "text", "triggerValue") SELECT "categoryId", "createdAt", "description", "id", "imageUrl", "noteRequired", "parentQuestionId", "points", "text", "triggerValue" FROM "Question";
DROP TABLE "Question";
ALTER TABLE "new_Question" RENAME TO "Question";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
