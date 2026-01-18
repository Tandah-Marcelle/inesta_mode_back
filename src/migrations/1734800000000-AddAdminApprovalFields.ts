import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddAdminApprovalFields1734800000000 implements MigrationInterface {
  name = 'AddAdminApprovalFields1734800000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create approval status enum
    await queryRunner.query(`
      CREATE TYPE "public"."users_approvalstatus_enum" AS ENUM('pending', 'approved', 'rejected')
    `);

    // Add approval fields to users table
    await queryRunner.query(`
      ALTER TABLE "users" 
      ADD COLUMN "approvalStatus" "public"."users_approvalstatus_enum" NOT NULL DEFAULT 'approved'
    `);

    await queryRunner.query(`
      ALTER TABLE "users" 
      ADD COLUMN "requestedAt" TIMESTAMP
    `);

    await queryRunner.query(`
      ALTER TABLE "users" 
      ADD COLUMN "approvedBy" uuid
    `);

    await queryRunner.query(`
      ALTER TABLE "users" 
      ADD COLUMN "approvedAt" TIMESTAMP
    `);

    await queryRunner.query(`
      ALTER TABLE "users" 
      ADD COLUMN "approvalComments" text
    `);

    await queryRunner.query(`
      ALTER TABLE "users" 
      ADD COLUMN "requestReason" text
    `);

    // Update existing admin users to have approved status
    await queryRunner.query(`
      UPDATE "users" 
      SET "approvalStatus" = 'approved', "approvedAt" = NOW()
      WHERE "role" IN ('admin', 'super_admin')
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Remove approval fields
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "requestReason"`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "approvalComments"`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "approvedAt"`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "approvedBy"`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "requestedAt"`);
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "approvalStatus"`);

    // Drop enum type
    await queryRunner.query(`DROP TYPE "public"."users_approvalstatus_enum"`);
  }
}