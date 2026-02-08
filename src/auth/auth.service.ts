import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { User, UserRole, ApprovalStatus } from '../entities/user.entity';
import { Permission, PermissionResource, PermissionAction } from '../entities/permission.entity';
import { UserPermission } from '../entities/user-permission.entity';
import { LoginDto, RegisterDto, AuthResponseDto, EnhancedAuthResponseDto } from './dto/auth.dto';
import { JwtPayload } from './jwt.strategy';
import { TokenBlacklistService } from './token-blacklist.service';
import { SecurityService, SecurityContext } from './security.service';

export interface MfaLoginDto extends LoginDto {
  mfaToken?: string;
}

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Permission)
    private readonly permissionRepository: Repository<Permission>,
    @InjectRepository(UserPermission)
    private readonly userPermissionRepository: Repository<UserPermission>,
    private readonly jwtService: JwtService,
    private readonly tokenBlacklistService: TokenBlacklistService,
    private readonly securityService: SecurityService,
  ) { }

  async register(registerDto: RegisterDto, context: SecurityContext): Promise<AuthResponseDto> {
    const { email, password, firstName, lastName, phone } = registerDto;

    // Check if user already exists
    const existingUser = await this.userRepository.findOne({
      where: { email },
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    // Validate password strength
    this.validatePasswordStrength(password);

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create new user
    const user = this.userRepository.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      phone,
      role: UserRole.USER,
      isActive: true,
      requirePasswordChange: false,
    });

    const savedUser = await this.userRepository.save(user);

    // Create session
    const sessionToken = await this.securityService.createSession(savedUser.id, context);

    // Generate JWT token
    const payload: JwtPayload = {
      sub: savedUser.id,
      email: savedUser.email,
      role: savedUser.role,
    };

    const access_token = this.jwtService.sign(payload);

    return {
      access_token,
      user: {
        id: savedUser.id,
        firstName: savedUser.firstName,
        lastName: savedUser.lastName,
        email: savedUser.email,
        role: savedUser.role,
      },
    };
  }

  async login(loginDto: MfaLoginDto, context: SecurityContext): Promise<EnhancedAuthResponseDto> {
    const { email, password, mfaToken } = loginDto;

    // Check if account is locked
    const isLocked = await this.securityService.isAccountLocked(email);
    if (isLocked) {
      throw new UnauthorizedException('Account is temporarily locked due to multiple failed login attempts');
    }

    // Find user by email
    const user = await this.userRepository.findOne({
      where: { email, isActive: true },
    });

    if (!user) {
      console.warn(`Login Failed: User not found or inactive. Email: ${email}`);
      await this.securityService.recordFailedLogin(email, context);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if admin account is pending approval
    if ((user.role === UserRole.ADMIN || user.role === UserRole.SUPER_ADMIN) && user.isPendingApproval) {
      console.warn(`Login Failed: Admin pending approval. Email: ${email}`);
      throw new UnauthorizedException('Your admin account is pending approval. Please wait for a super administrator to approve your request.');
    }

    // Check if admin account was rejected
    if ((user.role === UserRole.ADMIN || user.role === UserRole.SUPER_ADMIN) && user.approvalStatus === ApprovalStatus.REJECTED) {
      console.warn(`Login Failed: Admin rejected. Email: ${email}`);
      throw new UnauthorizedException('Your admin account request was rejected. Please contact a super administrator.');
    }

    // Check password
    console.log(`Debug Login: Email=${email}, PwdLen=${password.length}, HashLen=${user.password.length}, FirstChar=${password.charCodeAt(0)}, LastChar=${password.charCodeAt(password.length - 1)}`);

    // Check if the password is "TemporaryAdmin123!" explicitly to see if strictly equals
    if (password === 'TemporaryAdmin123!') {
      console.log('Debug Login: Password STRING matches hardcoded value exactly.');
    } else {
      console.log('Debug Login: Password STRING does NOT match hardcoded value.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.warn(`Login Failed: Invalid password for ${email}`);
      await this.securityService.recordFailedLogin(email, context);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if MFA is required
    if (user.isMfaEnabled) {
      if (!mfaToken) {
        return {
          access_token: null,
          user: null,
          requiresMfa: true,
        };
      }

      const isMfaValid = await this.securityService.verifyMfaToken(user.id, mfaToken);
      if (!isMfaValid) {
        await this.securityService.recordFailedLogin(email, context);
        throw new UnauthorizedException('Invalid MFA token');
      }
    }

    // Check if password change is required
    if (user.requirePasswordChange) {
      throw new UnauthorizedException('Password change required');
    }

    // Record successful login
    await this.securityService.recordSuccessfulLogin(user.id, context);

    // Create session
    const sessionToken = await this.securityService.createSession(user.id, context);

    // Generate JWT token
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    const access_token = this.jwtService.sign(payload);

    return {
      access_token,
      sessionToken,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
      },
    };
  }

  async validateUser(userId: string): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id: userId, isActive: true },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (user.isLocked) {
      throw new UnauthorizedException('Account is locked');
    }

    return user;
  }

  async logout(token: string, sessionToken?: string): Promise<{ message: string }> {
    // Add JWT token to blacklist
    this.tokenBlacklistService.blacklistToken(token);

    // Revoke session if provided
    if (sessionToken) {
      await this.securityService.revokeSession(sessionToken);
    }

    // Update user's last activity
    try {
      const decoded = this.jwtService.decode(token) as JwtPayload;
      if (decoded && decoded.sub) {
        await this.userRepository.update(
          { id: decoded.sub },
          { lastLoginAt: new Date() }
        );
      }
    } catch (error) {
      console.warn('Could not decode token for logout:', error.message);
    }

    return { message: 'Logout successful' };
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Validate new password strength
    this.validatePasswordStrength(newPassword);

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update password
    user.password = hashedPassword;
    user.passwordChangedAt = new Date();
    user.requirePasswordChange = false;
    await this.userRepository.save(user);

    // Revoke all sessions except current one
    await this.securityService.revokeAllUserSessions(userId);

    return { message: 'Password changed successfully' };
  }

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      // Don't reveal if email exists
      return { message: 'If the email exists, a reset link has been sent' };
    }

    const resetToken = await this.securityService.generatePasswordResetToken(user.id);

    // TODO: Send email with reset token
    // await this.emailService.sendPasswordResetEmail(user.email, resetToken);

    return { message: 'If the email exists, a reset link has been sent' };
  }

  async resetPassword(token: string, newPassword: string): Promise<{ message: string }> {
    this.validatePasswordStrength(newPassword);

    const success = await this.securityService.resetPassword(token, newPassword);
    if (!success) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    return { message: 'Password reset successfully' };
  }

  // MFA Methods
  async setupMfa(userId: string) {
    return this.securityService.setupMfa(userId);
  }

  async enableMfa(userId: string, token: string): Promise<{ message: string }> {
    const success = await this.securityService.enableMfa(userId, token);
    if (!success) {
      throw new BadRequestException('Invalid MFA token');
    }

    return { message: 'MFA enabled successfully' };
  }

  async disableMfa(userId: string, password: string): Promise<{ message: string }> {
    const success = await this.securityService.disableMfa(userId, password);
    if (!success) {
      throw new BadRequestException('Invalid password');
    }

    return { message: 'MFA disabled successfully' };
  }

  // Admin Methods
  async createSecureAdmin(createAdminDto: {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
    requestReason?: string;
  }): Promise<{ message: string; email: string; requiresApproval: boolean }> {
    const { firstName, lastName, email, password, requestReason } = createAdminDto;

    // Validate password strength
    this.validatePasswordStrength(password);

    // Check if admin already exists
    const existingAdmin = await this.userRepository.findOne({
      where: { email },
    });

    if (existingAdmin) {
      throw new ConflictException('User with this email already exists');
    }

    // Hash the provided password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create admin user with pending approval status
    const admin = this.userRepository.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      role: UserRole.ADMIN, // Will be admin once approved
      isActive: false, // Inactive until approved
      isEmailVerified: true,
      requirePasswordChange: false,
      approvalStatus: ApprovalStatus.PENDING,
      requestedAt: new Date(),
      requestReason: requestReason || 'Admin access request',
    });

    await this.userRepository.save(admin);

    // TODO: Send email notification to existing super admins
    // await this.notifySuperAdminsOfPendingRequest(admin);

    return {
      message: 'Admin request submitted successfully. Your account will be activated once approved by a super administrator.',
      email,
      requiresApproval: true,
    };
  }

  async getPendingAdminRequests(): Promise<User[]> {
    return this.userRepository.find({
      where: {
        role: UserRole.ADMIN,
        approvalStatus: ApprovalStatus.PENDING,
      },
      order: { requestedAt: 'DESC' },
    });
  }

  async approveAdminRequest(
    requestId: string,
    approverId: string,
    comments?: string
  ): Promise<{ message: string }> {
    const adminRequest = await this.userRepository.findOne({
      where: {
        id: requestId,
        approvalStatus: ApprovalStatus.PENDING,
      },
    });

    if (!adminRequest) {
      throw new BadRequestException('Admin request not found or already processed');
    }

    // Update the admin request
    adminRequest.approvalStatus = ApprovalStatus.APPROVED;
    adminRequest.approvedBy = approverId;
    adminRequest.approvedAt = new Date();
    adminRequest.approvalComments = comments || null;
    adminRequest.isActive = true; // Activate the account

    await this.userRepository.save(adminRequest);

    // Assign basic admin permissions
    await this.assignBasicAdminPermissions(adminRequest.id);

    // TODO: Send email notification to the approved admin
    // await this.emailService.sendApprovalNotification(adminRequest.email, true, comments);

    return { message: 'Admin request approved successfully' };
  }

  private async assignBasicAdminPermissions(userId: string): Promise<void> {
    // First, ensure permissions exist by seeding them if needed
    await this.ensurePermissionsExist();

    // Define basic admin permissions
    const basicAdminPermissions = [
      // Dashboard access
      { resource: PermissionResource.DASHBOARD, action: PermissionAction.VIEW },

      // Products management
      { resource: PermissionResource.PRODUCTS, action: PermissionAction.VIEW },
      { resource: PermissionResource.PRODUCTS, action: PermissionAction.CREATE },
      { resource: PermissionResource.PRODUCTS, action: PermissionAction.UPDATE },
      { resource: PermissionResource.PRODUCTS, action: PermissionAction.DELETE },

      // Categories management
      { resource: PermissionResource.CATEGORIES, action: PermissionAction.VIEW },
      { resource: PermissionResource.CATEGORIES, action: PermissionAction.CREATE },
      { resource: PermissionResource.CATEGORIES, action: PermissionAction.UPDATE },
      { resource: PermissionResource.CATEGORIES, action: PermissionAction.DELETE },

      // Users management - full access for admins
      { resource: PermissionResource.USERS, action: PermissionAction.VIEW },
      { resource: PermissionResource.USERS, action: PermissionAction.CREATE },
      { resource: PermissionResource.USERS, action: PermissionAction.UPDATE },
      { resource: PermissionResource.USERS, action: PermissionAction.DELETE },

      // Orders management
      { resource: PermissionResource.ORDERS, action: PermissionAction.VIEW },
      { resource: PermissionResource.ORDERS, action: PermissionAction.UPDATE },

      // Permissions management
      { resource: PermissionResource.PERMISSIONS, action: PermissionAction.VIEW },
      { resource: PermissionResource.PERMISSIONS, action: PermissionAction.UPDATE },

      // Content management
      { resource: PermissionResource.SETTINGS, action: PermissionAction.VIEW },

      // Contact messages
      { resource: PermissionResource.CONTACT_MESSAGES, action: PermissionAction.VIEW },
      { resource: PermissionResource.CONTACT_MESSAGES, action: PermissionAction.UPDATE },
    ];

    // Find and assign permissions
    for (const permissionData of basicAdminPermissions) {
      const permission = await this.permissionRepository.findOne({
        where: {
          resource: permissionData.resource,
          action: permissionData.action,
        },
      });

      if (permission) {
        // Check if permission already exists for this user
        const existingUserPermission = await this.userPermissionRepository.findOne({
          where: {
            userId: userId,
            permissionId: permission.id,
          },
        });

        if (!existingUserPermission) {
          // Create new user permission
          const userPermission = this.userPermissionRepository.create({
            userId: userId,
            permissionId: permission.id,
            isGranted: true,
          });

          await this.userPermissionRepository.save(userPermission);
        }
      }
    }
  }

  private async ensurePermissionsExist(): Promise<void> {
    // Check if permissions exist
    const permissionCount = await this.permissionRepository.count();

    if (permissionCount === 0) {
      // Seed basic permissions
      const basicPermissions = [
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

        // Contact Messages
        { resource: PermissionResource.CONTACT_MESSAGES, action: PermissionAction.VIEW, name: 'Voir les messages', description: 'Consulter les messages de contact' },
        { resource: PermissionResource.CONTACT_MESSAGES, action: PermissionAction.UPDATE, name: 'Traiter les messages', description: 'Marquer les messages comme lus/traités' },
        { resource: PermissionResource.CONTACT_MESSAGES, action: PermissionAction.DELETE, name: 'Supprimer les messages', description: 'Supprimer des messages de contact' },
      ];

      for (const permissionData of basicPermissions) {
        const existing = await this.permissionRepository.findOne({
          where: { resource: permissionData.resource, action: permissionData.action },
        });

        if (!existing) {
          const permission = this.permissionRepository.create(permissionData);
          await this.permissionRepository.save(permission);
        }
      }
    }
  }

  async rejectAdminRequest(
    requestId: string,
    approverId: string,
    comments?: string
  ): Promise<{ message: string }> {
    const adminRequest = await this.userRepository.findOne({
      where: {
        id: requestId,
        approvalStatus: ApprovalStatus.PENDING,
      },
    });

    if (!adminRequest) {
      throw new BadRequestException('Admin request not found or already processed');
    }

    // Update the admin request
    adminRequest.approvalStatus = ApprovalStatus.REJECTED;
    adminRequest.approvedBy = approverId;
    adminRequest.approvedAt = new Date();
    adminRequest.approvalComments = comments || null;

    await this.userRepository.save(adminRequest);

    // TODO: Send email notification to the rejected admin
    // await this.emailService.sendApprovalNotification(adminRequest.email, false, comments);

    return { message: 'Admin request rejected successfully' };
  }

  // Utility Methods
  private validatePasswordStrength(password: string): void {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) {
      throw new BadRequestException(`Password must be at least ${minLength} characters long`);
    }

    if (!hasUpperCase) {
      throw new BadRequestException('Password must contain at least one uppercase letter');
    }

    if (!hasLowerCase) {
      throw new BadRequestException('Password must contain at least one lowercase letter');
    }

    if (!hasNumbers) {
      throw new BadRequestException('Password must contain at least one number');
    }

    if (!hasSpecialChar) {
      throw new BadRequestException('Password must contain at least one special character');
    }
  }

  private generateSecurePassword(): string {
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
}
