import { Controller, Post, Get, Patch, Body, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service.js';
import { LoginDto } from './dto/login.dto.js';
import { ChangePasswordDto } from './dto/change-password.dto.js';
import { ForgotPasswordDto, ResetPasswordDto, UpdateDeviceTokenDto } from './dto/reset-password.dto.js';
import { RegisterDto } from './dto/register.dto.js';
import { CreateTenantDto } from './dto/create-tenant.dto.js';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard.js';
import { CurrentUser } from '../common/decorators/current-user.decorator.js';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  logout(@CurrentUser() user: { id: string }) {
    return this.authService.logout(user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@CurrentUser() user: { id: string; tenant_id: string | null }) {
    return this.authService.getProfile(user.id, user.tenant_id);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('change-password')
  changePassword(@CurrentUser() user: { id: string; email: string }, @Body() dto: ChangePasswordDto) {
    return this.authService.changePassword(user.id, user.email, dto);
  }

  @Post('forgot-password')
  forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto);
  }

  @Post('reset-password')
  resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('create-tenant')
  createTenant(@CurrentUser() user: { id: string }, @Body() dto: CreateTenantDto) {
    return this.authService.createTenant(user.id, dto);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('device-token')
  updateDeviceToken(@CurrentUser() user: { id: string }, @Body() dto: UpdateDeviceTokenDto) {
    return this.authService.updateDeviceToken(user.id, dto.device_token);
  }
}
