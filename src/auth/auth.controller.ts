import {
  Controller,
  Post,
  Get,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  UseGuards,
  Headers,
  Req,
  Param,
  Patch,
  BadRequestException,
  Query,
} from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto, AuthResponseDto } from './dto/auth.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './jwt.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtBlacklistGuard } from './guards/jwt-blacklist.guard';
import { RolesGuard } from './guards/roles.guard';
import { Roles } from './decorators/roles.decorator';
import { GetUser } from './decorators/get-user.decorator';
import { User, UserRole } from '../entities/user.entity';
import { TokenBlacklistService } from './token-blacklist.service';
import { SecurityContext } from './security.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly tokenBlacklistService: TokenBlacklistService,
    private readonly jwtService: JwtService,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly dataSource: DataSource,
  ) { }

  private getSecurityContext(req: Request): SecurityContext {
    return {
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      location: req.get('CF-IPCountry') || undefined, // Cloudflare country header
      device: this.parseDevice(req.get('User-Agent')),
    };
  }

  private parseDevice(userAgent?: string): string | undefined {
    if (!userAgent) return undefined;

    if (userAgent.includes('Mobile')) return 'Mobile';
    if (userAgent.includes('Tablet')) return 'Tablet';
    if (userAgent.includes('Windows')) return 'Windows PC';
    if (userAgent.includes('Mac')) return 'Mac';
    if (userAgent.includes('Linux')) return 'Linux PC';

    return 'Unknown Device';
  }

  @Get('debug-user-check')
  async debugUserCheck(@Query('email') email: string) {
    if (!email) return { error: 'Email required' };

    try {
      const user = await this.userRepository.findOne({ where: { email } });
      if (!user) {
        return {
          exists: false,
          message: 'No user found with this email at all'
        };
      }

      const testPass = 'TemporaryAdmin123!';
      const isMatch = await bcrypt.compare(testPass, user.password);

      return {
        exists: true,
        email: user.email,
        role: user.role,
        passwordHashPreview: user.password ? user.password.substring(0, 10) + '...' : 'NO_PASSWORD',
        doesMatchTempPassword: isMatch,
        isActive: user.isActive,
        approvalStatus: user.approvalStatus,
        isPending: user.approvalStatus === 'pending',
        failedLoginAttempts: user.failedLoginAttempts
      };
    } catch (error) {
      return {
        error: 'Debug check failed',
        details: error.message
      };
    }
  }

  @Post('register')
  async register(
    @Body(new ValidationPipe({ transform: true, whitelist: true }))
    registerDto: RegisterDto,
    @Req() req: Request,
  ): Promise<AuthResponseDto> {
    const context = this.getSecurityContext(req);
    return this.authService.register(registerDto, context);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body(new ValidationPipe({ transform: true, whitelist: true }))
    loginDto: LoginDto,
    @Req() req: Request,
  ) {
    const context = this.getSecurityContext(req);
    return this.authService.login(loginDto, context);
  }

  @Post('create-secure-admin')
  async createSecureAdmin(
    @Body() createAdminDto: {
      firstName: string;
      lastName: string;
      email: string;
      password: string;
      requestReason?: string;
    },
  ) {
    return this.authService.createSecureAdmin(createAdminDto);
  }

  // Admin Approval Endpoints
  @Get('admin/pending-requests')
  @UseGuards(JwtBlacklistGuard, RolesGuard)
  @Roles(UserRole.SUPER_ADMIN)
  async getPendingAdminRequests() {
    return this.authService.getPendingAdminRequests();
  }

  @Patch('admin/approve/:requestId')
  @UseGuards(JwtBlacklistGuard, RolesGuard)
  @Roles(UserRole.SUPER_ADMIN)
  async approveAdminRequest(
    @Param('requestId') requestId: string,
    @GetUser() approver: User,
    @Body('comments') comments?: string,
  ) {
    return this.authService.approveAdminRequest(requestId, approver.id, comments);
  }

  @Patch('admin/reject/:requestId')
  @UseGuards(JwtBlacklistGuard, RolesGuard)
  @Roles(UserRole.SUPER_ADMIN)
  async rejectAdminRequest(
    @Param('requestId') requestId: string,
    @GetUser() approver: User,
    @Body('comments') comments?: string,
  ) {
    return this.authService.rejectAdminRequest(requestId, approver.id, comments);
  }

  @Post('logout')
  @UseGuards(JwtBlacklistGuard)
  @HttpCode(HttpStatus.OK)
  async logout(@Headers('authorization') authHeader: string) {
    const token = this.tokenBlacklistService.extractToken(authHeader);
    if (!token) {
      return { message: 'No token provided' };
    }
    return this.authService.logout(token);
  }

  @Get('validate')
  @UseGuards(JwtBlacklistGuard)
  @HttpCode(HttpStatus.OK)
  async validateToken(@GetUser() user: User) {
    return {
      valid: true,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
      },
    };
  }

  @Get('me')
  @UseGuards(JwtBlacklistGuard)
  async getProfile(@GetUser() user: User) {
    // Fetch fresh user data from database
    const freshUser = await this.authService.validateUser(user.id);
    return {
      user: {
        id: freshUser.id,
        firstName: freshUser.firstName,
        lastName: freshUser.lastName,
        email: freshUser.email,
        role: freshUser.role,
      },
    };
  }

  // MFA Endpoints
  @Post('mfa/setup')
  @UseGuards(JwtBlacklistGuard)
  async setupMfa(@GetUser() user: User) {
    return this.authService.setupMfa(user.id);
  }

  @Post('mfa/enable')
  @UseGuards(JwtBlacklistGuard)
  async enableMfa(
    @GetUser() user: User,
    @Body('token') token: string,
  ) {
    return this.authService.enableMfa(user.id, token);
  }

  @Post('mfa/disable')
  @UseGuards(JwtBlacklistGuard)
  async disableMfa(
    @GetUser() user: User,
    @Body('password') password: string,
  ) {
    return this.authService.disableMfa(user.id, password);
  }

  // Password Management
  @Post('change-password')
  @UseGuards(JwtBlacklistGuard)
  async changePassword(
    @GetUser() user: User,
    @Body('currentPassword') currentPassword: string,
    @Body('newPassword') newPassword: string,
  ) {
    return this.authService.changePassword(user.id, currentPassword, newPassword);
  }

  @Post('request-password-reset')
  async requestPasswordReset(@Body('email') email: string) {
    return this.authService.requestPasswordReset(email);
  }

  @Post('reset-password')
  async resetPassword(
    @Body('token') token: string,
    @Body('newPassword') newPassword: string,
  ) {
    return this.authService.resetPassword(token, newPassword);
  }

  @Get('debug/current-user')
  @UseGuards(JwtBlacklistGuard)
  async getCurrentUserDebug(@GetUser() user: User) {
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName,
      isActive: user.isActive,
    };
  }

  @Post('refresh')
  @UseGuards(JwtBlacklistGuard)
  async refreshToken(@GetUser() user: User) {
    // Generate new JWT token
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    const access_token = this.jwtService.sign(payload);

    return {
      access_token,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
      },
    };
  }

  @Post('seed-permissions')
  @UseGuards(JwtBlacklistGuard, RolesGuard)
  @Roles(UserRole.SUPER_ADMIN)
  async seedPermissions() {
    // This is a temporary endpoint for seeding permissions
    // Should be removed in production
    try {
      const { seedPermissions } = await import('../seed/permissions.seed');
      await seedPermissions(this.dataSource);
      return { message: 'Permissions seeded successfully' };
    } catch (error) {
      throw new BadRequestException('Failed to seed permissions: ' + error.message);
    }
  }
}
