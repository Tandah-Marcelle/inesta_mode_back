import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdatePermissionResourceEnum1695466800000 implements MigrationInterface {
  name = 'UpdatePermissionResourceEnum1695466800000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // First, update any existing records with the old value
    await queryRunner.query(`
      UPDATE "permissions" 
      SET "resource" = 'contact-messages' 
      WHERE "resource" = 'contact_messages'
    `);

    // Drop the existing enum
    await queryRunner.query(`DROP TYPE IF EXISTS "public"."permissions_resource_enum"`);
    
    // Create the new enum with all values including the corrected ones
    await queryRunner.query(`
      CREATE TYPE "public"."permissions_resource_enum" AS ENUM(
        'dashboard', 
        'products', 
        'categories', 
        'users', 
        'orders', 
        'settings', 
        'news', 
        'partners', 
        'testimonials', 
        'contact-messages', 
        'auth', 
        'permissions'
      )
    `);

    // Update the column to use the new enum
    await queryRunner.query(`
      ALTER TABLE "permissions" 
      ALTER COLUMN "resource" TYPE "public"."permissions_resource_enum" 
      USING "resource"::"text"::"public"."permissions_resource_enum"
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Revert back to the old enum format
    await queryRunner.query(`
      UPDATE "permissions" 
      SET "resource" = 'contact_messages' 
      WHERE "resource" = 'contact-messages'
    `);

    // Drop the current enum
    await queryRunner.query(`DROP TYPE IF EXISTS "public"."permissions_resource_enum"`);
    
    // Create the old enum
    await queryRunner.query(`
      CREATE TYPE "public"."permissions_resource_enum" AS ENUM(
        'dashboard', 
        'products', 
        'categories', 
        'users', 
        'orders', 
        'settings', 
        'news', 
        'partners', 
        'testimonials', 
        'contact_messages', 
        'auth'
      )
    `);

    // Update the column to use the old enum
    await queryRunner.query(`
      ALTER TABLE "permissions" 
      ALTER COLUMN "resource" TYPE "public"."permissions_resource_enum" 
      USING "resource"::"text"::"public"."permissions_resource_enum"
    `);
  }
}