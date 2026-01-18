import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddSecurityFeatures1734659200000 implements MigrationInterface {
  name = 'AddSecurityFeatures1734659200000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add security fields to users table
    await queryRunner.query(`
      ALTER TABLE "users" 
      ADD COLUMN "isMfaEnabled" boolean NOT NULL DEFAULT false,
      ADD COLUMN "mfaSecret" varchar(255),
      ADD COLUMN "backupCodes" json,
      ADD COLUMN "failedLoginAttempts" integer NOT NULL DEFAULT 0,
      ADD COLUMN "lockedUntil" timestamp,
      ADD COLUMN "passwordResetToken" varchar(255),
      ADD COLUMN "passwordResetExpires" timestamp,
      ADD COLUMN "emailVerificationToken" varchar(255),
      ADD COLUMN "emailVerificationExpires" timestamp,
      ADD COLUMN "passwordChangedAt" timestamp,
      ADD COLUMN "requirePasswordChange" boolean NOT NULL DEFAULT false,
      ADD COLUMN "lastLoginIp" varchar(45),
      ADD COLUMN "lastLoginUserAgent" text
    `);

    // Create user_sessions table
    await queryRunner.query(`
      CREATE TABLE "user_sessions" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "userId" uuid NOT NULL,
        "sessionToken" varchar(255) NOT NULL,
        "ipAddress" varchar(45),
        "userAgent" text,
        "location" varchar(100),
        "device" varchar(100),
        "isActive" boolean NOT NULL DEFAULT true,
        "expiresAt" timestamp NOT NULL,
        "lastActivityAt" timestamp,
        "createdAt" timestamp NOT NULL DEFAULT now(),
        "updatedAt" timestamp NOT NULL DEFAULT now(),
        CONSTRAINT "PK_user_sessions" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_user_sessions_sessionToken" UNIQUE ("sessionToken"),
        CONSTRAINT "FK_user_sessions_userId" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE
      )
    `);

    // Create security_logs table
    await queryRunner.query(`
      CREATE TYPE "security_event_type_enum" AS ENUM (
        'login_success', 'login_failed', 'login_blocked', 'logout',
        'password_changed', 'password_reset_requested', 'password_reset_completed',
        'mfa_enabled', 'mfa_disabled', 'mfa_backup_used',
        'account_locked', 'account_unlocked', 'email_verified',
        'suspicious_activity', 'permission_changed'
      )
    `);

    await queryRunner.query(`
      CREATE TYPE "security_risk_level_enum" AS ENUM ('low', 'medium', 'high', 'critical')
    `);

    await queryRunner.query(`
      CREATE TABLE "security_logs" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "userId" uuid,
        "eventType" "security_event_type_enum" NOT NULL,
        "riskLevel" "security_risk_level_enum" NOT NULL DEFAULT 'low',
        "description" varchar(255) NOT NULL,
        "ipAddress" varchar(45),
        "userAgent" text,
        "location" varchar(100),
        "metadata" json,
        "isResolved" boolean NOT NULL DEFAULT false,
        "resolution" text,
        "createdAt" timestamp NOT NULL DEFAULT now(),
        CONSTRAINT "PK_security_logs" PRIMARY KEY ("id"),
        CONSTRAINT "FK_security_logs_userId" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL
      )
    `);

    // Create indexes for better performance
    await queryRunner.query(`CREATE INDEX "IDX_user_sessions_userId" ON "user_sessions" ("userId")`);
    await queryRunner.query(`CREATE INDEX "IDX_user_sessions_sessionToken" ON "user_sessions" ("sessionToken")`);
    await queryRunner.query(`CREATE INDEX "IDX_user_sessions_expiresAt" ON "user_sessions" ("expiresAt")`);
    await queryRunner.query(`CREATE INDEX "IDX_security_logs_userId" ON "security_logs" ("userId")`);
    await queryRunner.query(`CREATE INDEX "IDX_security_logs_eventType" ON "security_logs" ("eventType")`);
    await queryRunner.query(`CREATE INDEX "IDX_security_logs_riskLevel" ON "security_logs" ("riskLevel")`);
    await queryRunner.query(`CREATE INDEX "IDX_security_logs_createdAt" ON "security_logs" ("createdAt")`);
    await queryRunner.query(`CREATE INDEX "IDX_users_email" ON "users" ("email")`);
    await queryRunner.query(`CREATE INDEX "IDX_users_passwordResetToken" ON "users" ("passwordResetToken")`);
    await queryRunner.query(`CREATE INDEX "IDX_users_emailVerificationToken" ON "users" ("emailVerificationToken")`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop indexes
    await queryRunner.query(`DROP INDEX "IDX_users_emailVerificationToken"`);
    await queryRunner.query(`DROP INDEX "IDX_users_passwordResetToken"`);
    await queryRunner.query(`DROP INDEX "IDX_users_email"`);
    await queryRunner.query(`DROP INDEX "IDX_security_logs_createdAt"`);
    await queryRunner.query(`DROP INDEX "IDX_security_logs_riskLevel"`);
    await queryRunner.query(`DROP INDEX "IDX_security_logs_eventType"`);
    await queryRunner.query(`DROP INDEX "IDX_security_logs_userId"`);
    await queryRunner.query(`DROP INDEX "IDX_user_sessions_expiresAt"`);
    await queryRunner.query(`DROP INDEX "IDX_user_sessions_sessionToken"`);
    await queryRunner.query(`DROP INDEX "IDX_user_sessions_userId"`);

    // Drop tables
    await queryRunner.query(`DROP TABLE "security_logs"`);
    await queryRunner.query(`DROP TABLE "user_sessions"`);

    // Drop enums
    await queryRunner.query(`DROP TYPE "security_risk_level_enum"`);
    await queryRunner.query(`DROP TYPE "security_event_type_enum"`);

    // Remove security fields from users table
    await queryRunner.query(`
      ALTER TABLE "users" 
      DROP COLUMN "lastLoginUserAgent",
      DROP COLUMN "lastLoginIp",
      DROP COLUMN "requirePasswordChange",
      DROP COLUMN "passwordChangedAt",
      DROP COLUMN "emailVerificationExpires",
      DROP COLUMN "emailVerificationToken",
      DROP COLUMN "passwordResetExpires",
      DROP COLUMN "passwordResetToken",
      DROP COLUMN "lockedUntil",
      DROP COLUMN "failedLoginAttempts",
      DROP COLUMN "backupCodes",
      DROP COLUMN "mfaSecret",
      DROP COLUMN "isMfaEnabled"
    `);
  }
}