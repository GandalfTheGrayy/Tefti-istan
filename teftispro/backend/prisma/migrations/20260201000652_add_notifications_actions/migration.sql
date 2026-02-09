-- AlterTable
ALTER TABLE "Audit" ADD COLUMN "latitude" REAL;
ALTER TABLE "Audit" ADD COLUMN "longitude" REAL;

-- AlterTable
ALTER TABLE "Photo" ADD COLUMN "latitude" REAL;
ALTER TABLE "Photo" ADD COLUMN "longitude" REAL;

-- CreateTable
CREATE TABLE "Notification" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "userId" INTEGER NOT NULL,
    "title" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "read" BOOLEAN NOT NULL DEFAULT false,
    "auditId" INTEGER,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Notification_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "CorrectiveAction" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "auditId" INTEGER NOT NULL,
    "questionId" INTEGER NOT NULL,
    "answerId" INTEGER,
    "description" TEXT NOT NULL,
    "assignedTo" INTEGER,
    "dueDate" DATETIME,
    "status" TEXT NOT NULL DEFAULT 'open',
    "closedAt" DATETIME,
    "closedNote" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "CorrectiveAction_auditId_fkey" FOREIGN KEY ("auditId") REFERENCES "Audit" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "CorrectiveAction_questionId_fkey" FOREIGN KEY ("questionId") REFERENCES "Question" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

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
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "parentQuestionId" INTEGER,
    "triggerValue" TEXT,
    CONSTRAINT "Question_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "Category" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "Question_parentQuestionId_fkey" FOREIGN KEY ("parentQuestionId") REFERENCES "Question" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_Question" ("categoryId", "createdAt", "description", "id", "imageUrl", "noteRequired", "points", "text") SELECT "categoryId", "createdAt", "description", "id", "imageUrl", "noteRequired", "points", "text" FROM "Question";
DROP TABLE "Question";
ALTER TABLE "new_Question" RENAME TO "Question";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
