import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';
import { UserPermission } from '../../entities/user-permission.entity';

export interface RequiredPermission {
  resource: string;
  action: string;
}

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    @InjectRepository(UserPermission)
    private readonly userPermissionRepository: Repository<UserPermission>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.getAllAndOverride<RequiredPermission[]>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredPermissions) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    
    if (!user) {
      console.log('PermissionsGuard: No user found in request');
      return false;
    }

    console.log(`PermissionsGuard: User ${user.email} (role: ${user.role}) requesting access to:`, requiredPermissions);

    // Super admin has all permissions
    if (user.role === 'super_admin') {
      console.log('PermissionsGuard: Super admin access granted');
      return true;
    }

    // Regular admin has broad permissions by default - only check for sensitive operations
    if (user.role === 'admin') {
      console.log('PermissionsGuard: Admin user detected - granting broad access');
      
      // Admins have access to most operations by default
      // Only restrict very sensitive operations that require explicit permissions
      const restrictedOperations = [
        'permissions:update', // Managing permissions
        'users:delete',       // Deleting users
        'settings:update'     // System settings
      ];
      
      const hasRestrictedOperation = requiredPermissions.some(permission => 
        restrictedOperations.includes(`${permission.resource}:${permission.action}`)
      );
      
      if (hasRestrictedOperation) {
        console.log('PermissionsGuard: Admin requesting restricted operation, checking explicit permissions...');
        // For restricted operations, check explicit permissions
        for (const permission of requiredPermissions) {
          const hasPermission = await this.checkUserPermission(
            user.id,
            permission.resource,
            permission.action,
          );
          console.log(`PermissionsGuard: Admin permission check for ${permission.resource}:${permission.action} = ${hasPermission}`);
          
          if (!hasPermission) {
            console.log(`PermissionsGuard: Admin access denied - missing permission ${permission.resource}:${permission.action}`);
            return false;
          }
        }
      }
      
      console.log('PermissionsGuard: Admin access granted');
      return true;
    }

    // For other roles (user, utilisateur), check permissions normally
    console.log('PermissionsGuard: Checking user/utilisateur permissions...');
    for (const permission of requiredPermissions) {
      const hasPermission = await this.checkUserPermission(
        user.id,
        permission.resource,
        permission.action,
      );
      console.log(`PermissionsGuard: User permission check for ${permission.resource}:${permission.action} = ${hasPermission}`);
      
      if (!hasPermission) {
        console.log(`PermissionsGuard: User access denied - missing permission ${permission.resource}:${permission.action}`);
        return false;
      }
    }

    console.log('PermissionsGuard: User access granted');
    return true;
  }

  private async checkUserPermission(
    userId: string,
    resource: string,
    action: string,
  ): Promise<boolean> {
    const userPermission = await this.userPermissionRepository
      .createQueryBuilder('up')
      .leftJoinAndSelect('up.permission', 'p')
      .where('up.userId = :userId', { userId })
      .andWhere('up.isGranted = :isGranted', { isGranted: true })
      .andWhere('p.resource = :resource', { resource })
      .andWhere('p.action = :action', { action })
      .getOne();

    return !!userPermission;
  }
}