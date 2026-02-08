import { DataSource } from 'typeorm';
import { Permission, PermissionResource, PermissionAction } from '../entities/permission.entity';
import { User, UserRole } from '../entities/user.entity';
import { UserPermission } from '../entities/user-permission.entity';
import * as bcrypt from 'bcryptjs';

export async function seedPermissions(dataSource: DataSource) {
  const permissionRepository = dataSource.getRepository(Permission);

  const permissions = [
    // Dashboard
    { resource: PermissionResource.DASHBOARD, action: PermissionAction.VIEW, name: 'Voir le tableau de bord', description: 'Accès au tableau de bord principal' },

    // Products
    { resource: PermissionResource.PRODUCTS, action: PermissionAction.VIEW, name: 'Voir les produits', description: 'Consulter la liste des produits' },
    { resource: PermissionResource.PRODUCTS, action: PermissionAction.CREATE, name: 'Créer des produits', description: 'Ajouter de nouveaux produits' },
    { resource: PermissionResource.PRODUCTS, action: PermissionAction.UPDATE, name: 'Modifier les produits', description: 'Modifier les produits existants' },
    { resource: PermissionResource.PRODUCTS, action: PermissionAction.DELETE, name: 'Supprimer les produits', description: 'Supprimer des produits' },

    // Categories
    { resource: PermissionResource.CATEGORIES, action: PermissionAction.VIEW, name: 'Voir les catégories', description: 'Consulter la liste des catégories' },
    { resource: PermissionResource.CATEGORIES, action: PermissionAction.CREATE, name: 'Créer des catégories', description: 'Ajouter de nouvelles catégories' },
    { resource: PermissionResource.CATEGORIES, action: PermissionAction.UPDATE, name: 'Modifier les catégories', description: 'Modifier les catégories existantes' },
    { resource: PermissionResource.CATEGORIES, action: PermissionAction.DELETE, name: 'Supprimer les catégories', description: 'Supprimer des catégories' },

    // Users
    { resource: PermissionResource.USERS, action: PermissionAction.VIEW, name: 'Voir les utilisateurs', description: 'Consulter la liste des utilisateurs' },
    { resource: PermissionResource.USERS, action: PermissionAction.CREATE, name: 'Créer des utilisateurs', description: 'Ajouter de nouveaux utilisateurs' },
    { resource: PermissionResource.USERS, action: PermissionAction.UPDATE, name: 'Modifier les utilisateurs', description: 'Modifier les utilisateurs existants' },
    { resource: PermissionResource.USERS, action: PermissionAction.DELETE, name: 'Supprimer les utilisateurs', description: 'Supprimer des utilisateurs' },

    // Orders
    { resource: PermissionResource.ORDERS, action: PermissionAction.VIEW, name: 'Voir les commandes', description: 'Consulter la liste des commandes' },
    { resource: PermissionResource.ORDERS, action: PermissionAction.UPDATE, name: 'Modifier les commandes', description: 'Modifier le statut des commandes' },

    // Settings
    { resource: PermissionResource.SETTINGS, action: PermissionAction.VIEW, name: 'Voir les paramètres', description: 'Accès aux paramètres système' },
    { resource: PermissionResource.SETTINGS, action: PermissionAction.UPDATE, name: 'Modifier les paramètres', description: 'Modifier les paramètres système' },

    // News (Actualités & Événements)
    { resource: PermissionResource.NEWS, action: PermissionAction.VIEW, name: 'Voir les actualités', description: 'Consulter la liste des actualités et événements' },
    { resource: PermissionResource.NEWS, action: PermissionAction.CREATE, name: 'Créer des actualités', description: 'Ajouter de nouvelles actualités et événements' },
    { resource: PermissionResource.NEWS, action: PermissionAction.UPDATE, name: 'Modifier les actualités', description: 'Modifier les actualités et événements existants' },
    { resource: PermissionResource.NEWS, action: PermissionAction.DELETE, name: 'Supprimer les actualités', description: 'Supprimer des actualités et événements' },

    // Partners (Partenaires)
    { resource: PermissionResource.PARTNERS, action: PermissionAction.VIEW, name: 'Voir les partenaires', description: 'Consulter la liste des partenaires humanitaires' },
    { resource: PermissionResource.PARTNERS, action: PermissionAction.CREATE, name: 'Créer des partenaires', description: 'Ajouter de nouveaux partenaires' },
    { resource: PermissionResource.PARTNERS, action: PermissionAction.UPDATE, name: 'Modifier les partenaires', description: 'Modifier les partenaires existants' },
    { resource: PermissionResource.PARTNERS, action: PermissionAction.DELETE, name: 'Supprimer les partenaires', description: 'Supprimer des partenaires' },

    // Testimonials (Témoignages)
    { resource: PermissionResource.TESTIMONIALS, action: PermissionAction.VIEW, name: 'Voir les témoignages', description: 'Consulter la liste des témoignages clients' },
    { resource: PermissionResource.TESTIMONIALS, action: PermissionAction.CREATE, name: 'Créer des témoignages', description: 'Ajouter de nouveaux témoignages' },
    { resource: PermissionResource.TESTIMONIALS, action: PermissionAction.UPDATE, name: 'Modifier les témoignages', description: 'Modifier les témoignages existants' },
    { resource: PermissionResource.TESTIMONIALS, action: PermissionAction.DELETE, name: 'Supprimer les témoignages', description: 'Supprimer des témoignages' },

    // Contact Messages (Messages de contact)
    { resource: PermissionResource.CONTACT_MESSAGES, action: PermissionAction.VIEW, name: 'Voir les messages', description: 'Consulter les messages de contact' },
    { resource: PermissionResource.CONTACT_MESSAGES, action: PermissionAction.UPDATE, name: 'Traiter les messages', description: 'Marquer les messages comme lus/traités' },
    { resource: PermissionResource.CONTACT_MESSAGES, action: PermissionAction.DELETE, name: 'Supprimer les messages', description: 'Supprimer des messages de contact' },

    // Auth (Authentication & Authorization)
    { resource: PermissionResource.AUTH, action: PermissionAction.VIEW, name: 'Voir les sessions', description: 'Consulter les sessions utilisateurs' },
    { resource: PermissionResource.AUTH, action: PermissionAction.UPDATE, name: 'Gérer les accès', description: 'Révoquer des sessions et gérer les accès' },

    // Permissions (Gestion des permissions)
    { resource: PermissionResource.PERMISSIONS, action: PermissionAction.VIEW, name: 'Voir les permissions', description: 'Consulter les permissions disponibles' },
    { resource: PermissionResource.PERMISSIONS, action: PermissionAction.UPDATE, name: 'Gérer les permissions', description: 'Attribuer et révoquer des permissions' },
  ];

  for (const permissionData of permissions) {
    const existing = await permissionRepository.findOne({
      where: { resource: permissionData.resource, action: permissionData.action },
    });

    if (!existing) {
      const permission = permissionRepository.create(permissionData);
      await permissionRepository.save(permission);
      console.log(`Created permission: ${permissionData.name}`);
    }
  }

  console.log('Permissions seeding completed');

  // Create super admin user with secure setup
  const userRepository = dataSource.getRepository(User);
  const userPermissionRepository = dataSource.getRepository(UserPermission);

  let superAdmin = await userRepository.findOne({ where: { email: 'admin@inestamode.com' } });

  if (!superAdmin) {
    // Generate a secure temporary password
    const tempPassword = 'TemporaryAdmin123!'; // Hardcoded for debugging
    const hashedPassword = await bcrypt.hash(tempPassword, 12);

    superAdmin = userRepository.create({
      firstName: 'Super',
      lastName: 'Admin',
      email: 'admin@inestamode.com',
      password: hashedPassword,
      role: UserRole.SUPER_ADMIN,
      isActive: true,
      isEmailVerified: true,
      requirePasswordChange: true, // Force password change on first login
    });
    superAdmin = await userRepository.save(superAdmin);

    console.log('🔐 SUPER ADMIN CREATED');
    console.log(`Email: admin@inestamode.com`);
    console.log(`Password: ${tempPassword}`);
  } else {
    // Force reset password for debugging
    const tempPassword = 'TemporaryAdmin123!';
    const hashedPassword = await bcrypt.hash(tempPassword, 12);
    superAdmin.password = hashedPassword;
    await userRepository.save(superAdmin);

    console.log('🔐 SUPER ADMIN PASSWORD RESET');
    console.log(`Email: admin@inestamode.com`);
    console.log(`Password: ${tempPassword}`);
  }

  // Give super admin all permissions
  const allPermissions = await permissionRepository.find();
  for (const permission of allPermissions) {
    const existing = await userPermissionRepository.findOne({
      where: { userId: superAdmin.id, permissionId: permission.id }
    });

    if (!existing) {
      await userPermissionRepository.save({
        userId: superAdmin.id,
        permissionId: permission.id,
        isGranted: true,
      });
    }
  }

  console.log('Super admin permissions assigned');

  // Also reset password for tandahmarcelle2@gmail.com if it exists
  let userTandah = await userRepository.findOne({ where: { email: 'tandahmarcelle2@gmail.com' } });
  if (userTandah) {
    const tempPassword = 'TemporaryAdmin123!';
    const hashedPassword = await bcrypt.hash(tempPassword, 12);
    userTandah.password = hashedPassword;
    // Ensure it has admin role if needed, or leave as is
    if (userTandah.role !== UserRole.SUPER_ADMIN && userTandah.role !== UserRole.ADMIN) {
      userTandah.role = UserRole.SUPER_ADMIN; // Upgrade to Super Admin to fix permission issues
    }
    await userRepository.save(userTandah);
    console.log('🔐 USER TANDAH PASSWORD RESET');
    console.log(`Email: tandahmarcelle2@gmail.com`);
    console.log(`Password: ${tempPassword}`);
  }
}

// Utility function to generate secure passwords
function generateSecurePassword(): string {
  const length = 16;
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  let password = '';

  // Ensure at least one character from each required category
  password += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)]; // uppercase
  password += 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)]; // lowercase
  password += '0123456789'[Math.floor(Math.random() * 10)]; // number
  password += '!@#$%^&*'[Math.floor(Math.random() * 8)]; // special char

  // Fill the rest randomly
  for (let i = 4; i < length; i++) {
    password += charset[Math.floor(Math.random() * charset.length)];
  }

  // Shuffle the password
  return password.split('').sort(() => Math.random() - 0.5).join('');
}
