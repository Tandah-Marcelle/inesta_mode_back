import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdateUserRoles1734012000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Update existing 'customer' roles to 'user'
    await queryRunner.query(`UPDATE "users" SET "role" = 'user' WHERE "role" = 'customer'`);
    
    // Update existing 'admin' roles to 'admin' (no change needed but for consistency)
    await queryRunner.query(`UPDATE "users" SET "role" = 'admin' WHERE "role" = 'admin'`);
    
    // Now update the enum type
    await queryRunner.query(`ALTER TYPE "public"."users_role_enum" RENAME TO "users_role_enum_old"`);
    await queryRunner.query(`CREATE TYPE "public"."users_role_enum" AS ENUM('super_admin', 'admin', 'user')`);
    await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "role" TYPE "public"."users_role_enum" USING "role"::text::"public"."users_role_enum"`);
    await queryRunner.query(`DROP TYPE "public"."users_role_enum_old"`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Revert the enum type
    await queryRunner.query(`ALTER TYPE "public"."users_role_enum" RENAME TO "users_role_enum_old"`);
    await queryRunner.query(`CREATE TYPE "public"."users_role_enum" AS ENUM('admin', 'customer')`);
    await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "role" TYPE "public"."users_role_enum" USING "role"::text::"public"."users_role_enum"`);
    await queryRunner.query(`DROP TYPE "public"."users_role_enum_old"`);
    
    // Revert the role values
    await queryRunner.query(`UPDATE "users" SET "role" = 'customer' WHERE "role" = 'user'`);
  }
}