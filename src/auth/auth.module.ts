import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt.strategy';
import { TokenBlacklistService } from './token-blacklist.service';
import { SecurityService } from './security.service';
import { JwtBlacklistGuard } from './guards/jwt-blacklist.guard';
import { PermissionsGuard } from './guards/permissions.guard';
import { User } from '../entities/user.entity';
import { Permission } from '../entities/permission.entity';
import { UserPermission } from '../entities/user-permission.entity';
import { UserSession } from '../entities/user-session.entity';
import { SecurityLog } from '../entities/security-log.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, Permission, UserPermission, UserSession, SecurityLog]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRES_IN', '1d'),
        },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [AuthService, JwtStrategy, TokenBlacklistService, SecurityService, JwtBlacklistGuard, PermissionsGuard],
  controllers: [AuthController],
  exports: [AuthService, JwtStrategy, TokenBlacklistService, SecurityService, JwtBlacklistGuard, PermissionsGuard, PassportModule],
})
export class AuthModule {}
