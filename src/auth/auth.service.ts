import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service.js';
import { RedisService } from '../redis/redis.service.js';
import { EmailService } from '../email/email.service.js';
import { LoginDto } from './dto/login.dto.js';
import { ChangePasswordDto } from './dto/change-password.dto.js';
import { ForgotPasswordDto, ResetPasswordDto } from './dto/reset-password.dto.js';
import { RegisterDto } from './dto/register.dto.js';

function generateSlug(name: string): string {
  return name
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .substring(0, 50);
}

@Injectable()
export class AuthService {
  constructor(
    private supabase: SupabaseService,
    private redis: RedisService,
    private emailService: EmailService,
  ) {}

  async register(dto: RegisterDto) {
    // 1. Create auth user (trigger auto-creates public.users)
    const { data: authData, error } = await this.supabase.db.auth.admin.createUser({
      email: dto.email,
      password: dto.password,
      email_confirm: true,
      user_metadata: { full_name: dto.full_name },
    });

    if (error) {
      if (error.message.toLowerCase().includes('already')) {
        throw new ConflictException({ code: 'EMAIL_ALREADY_EXISTS', message: 'Email already registered' });
      }
      throw new BadRequestException(error.message);
    }

    // 2. Update public.users with full_name
    await this.supabase.db
      .from('users')
      .update({ full_name: dto.full_name })
      .eq('id', authData.user.id);

    // 3. Generate/validate slug
    const slug = dto.tenant_slug ?? generateSlug(dto.tenant_name);

    const { data: existingTenant } = await this.supabase.db
      .from('tenants')
      .select('id')
      .eq('slug', slug)
      .single();

    if (existingTenant) {
      await this.supabase.db.auth.admin.deleteUser(authData.user.id);
      throw new ConflictException({ code: 'SLUG_ALREADY_EXISTS', message: 'Tenant slug already taken' });
    }

    // 4. Create tenant
    const { data: tenant, error: tenantError } = await this.supabase.db
      .from('tenants')
      .insert({ name: dto.tenant_name, slug })
      .select()
      .single();

    if (tenantError) {
      await this.supabase.db.auth.admin.deleteUser(authData.user.id);
      throw new BadRequestException(tenantError.message);
    }

    // 5. Add to user_tenants as business_owner
    await this.supabase.db.from('user_tenants').insert({
      user_id: authData.user.id,
      tenant_id: tenant.id,
      role: 'business_owner',
    });

    // 6. Sign in to get Supabase session
    const { data: sessionData, error: signInError } = await this.supabase.authClient.auth.signInWithPassword({
      email: dto.email,
      password: dto.password,
    });

    if (signInError || !sessionData.session) {
      throw new BadRequestException('Registration succeeded but session creation failed');
    }

    return {
      access_token: sessionData.session.access_token,
      refresh_token: sessionData.session.refresh_token,
      user: {
        id: authData.user.id,
        email: dto.email,
        full_name: dto.full_name,
        role: 'business_owner',
        tenant_id: tenant.id,
      },
      tenant: { id: tenant.id, name: tenant.name, slug: tenant.slug },
    };
  }

  async login(dto: LoginDto) {
    const { data, error } = await this.supabase.authClient.auth.signInWithPassword({
      email: dto.email,
      password: dto.password,
    });

    if (error || !data.user || !data.session) {
      throw new UnauthorizedException({ code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' });
    }

    const { data: user, error: userError } = await this.supabase.db
      .from('users')
      .select('*')
      .eq('id', data.user.id)
      .eq('is_active', true)
      .single();

    if (userError || !user) {
      throw new UnauthorizedException({ code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' });
    }

    await this.supabase.db
      .from('users')
      .update({ last_login_at: new Date().toISOString() })
      .eq('id', user.id);

    const tokens = {
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
    };

    // Superadmin: issue immediately
    if (user.role === 'superadmin') {
      return {
        ...tokens,
        user: {
          id: user.id,
          email: user.email,
          full_name: user.full_name,
          role: user.role,
          tenant_id: null,
          avatar_url: user.avatar_url,
        },
      };
    }

    // Query active tenant memberships
    const { data: memberships } = await this.supabase.db
      .from('user_tenants')
      .select('role, tenant_id, tenants!inner(id, name, slug, status)')
      .eq('user_id', user.id)
      .eq('is_active', true)
      .eq('tenants.status', 'active');

    if (!memberships || memberships.length === 0) {
      throw new ForbiddenException({ code: 'FORBIDDEN', message: 'No active tenant memberships' });
    }

    const tenants = (memberships as any[]).map((m) => ({
      id: m.tenants.id,
      name: m.tenants.name,
      slug: m.tenants.slug,
      role: m.role,
    }));

    const userInfo = {
      id: user.id,
      email: user.email,
      full_name: user.full_name,
      avatar_url: user.avatar_url,
    };

    // Single tenant: return with tenant context
    if (memberships.length === 1) {
      const m = memberships[0] as any;
      return {
        ...tokens,
        user: { ...userInfo, role: m.role, tenant_id: m.tenant_id },
        tenants,
      };
    }

    // Multiple tenants: client picks one (token already issued)
    return {
      ...tokens,
      user: userInfo,
      tenants,
      requires_tenant_selection: true,
    };
  }

  async logout(userId: string) {
    await this.supabase.db
      .from('users')
      .update({ device_token: null })
      .eq('id', userId);
    return { message: 'Logged out successfully' };
  }

  async changePassword(userId: string, email: string, dto: ChangePasswordDto) {
    if (dto.new_password !== dto.confirm_password) {
      throw new BadRequestException({ code: 'PASSWORD_MISMATCH', message: 'Mật khẩu nhập lại không khớp' });
    }

    const { error } = await this.supabase.authClient.auth.signInWithPassword({
      email,
      password: dto.current_password,
    });

    if (error) {
      throw new BadRequestException({ code: 'INVALID_PASSWORD', message: 'Current password is incorrect' });
    }

    const { error: updateError } = await this.supabase.db.auth.admin.updateUserById(userId, {
      password: dto.new_password,
    });

    if (updateError) throw new BadRequestException(updateError.message);
    return { message: 'Password changed successfully' };
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    const { data: user } = await this.supabase.db
      .from('users')
      .select('id')
      .eq('email', dto.email)
      .single();

    if (!user) return { message: 'If that email exists, an OTP has been sent' };

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await this.redis.setOtp(dto.email, otp);
    await this.emailService.sendOtpEmail(dto.email, otp);

    return { message: 'If that email exists, an OTP has been sent' };
  }

  async resetPassword(dto: ResetPasswordDto) {
    if (dto.new_password !== dto.confirm_password) {
      throw new BadRequestException({ code: 'PASSWORD_MISMATCH', message: 'Mật khẩu nhập lại không khớp' });
    }

    const storedOtp = await this.redis.getOtp(dto.email);
    if (!storedOtp || storedOtp !== dto.otp) {
      throw new BadRequestException({ code: 'INVALID_OTP', message: 'Invalid or expired OTP' });
    }

    const { data: user } = await this.supabase.db
      .from('users')
      .select('id')
      .eq('email', dto.email)
      .single();

    if (!user) throw new NotFoundException({ code: 'USER_NOT_FOUND', message: 'User not found' });

    const { error } = await this.supabase.db.auth.admin.updateUserById(user.id, {
      password: dto.new_password,
    });

    if (error) throw new BadRequestException(error.message);
    await this.redis.deleteOtp(dto.email);

    return { message: 'Password reset successfully' };
  }

  async getProfile(userId: string, tenantId: string | null) {
    const { data: user, error } = await this.supabase.db
      .from('users')
      .select('id, email, full_name, role, phone, avatar_url, last_login_at, created_at, is_active')
      .eq('id', userId)
      .single();

    if (error || !user) throw new NotFoundException({ code: 'USER_NOT_FOUND', message: 'User not found' });

    if (user.role === 'superadmin') {
      return { ...user, tenant_id: null, tenants: [] };
    }

    // Fetch all tenant memberships for this user
    const { data: memberships } = await this.supabase.db
      .from('user_tenants')
      .select('role, tenant_id, tenants!inner(id, name, slug, status)')
      .eq('user_id', userId)
      .eq('is_active', true)
      .eq('tenants.status', 'active');

    const tenants = (memberships ?? []).map((m: any) => ({
      id: m.tenants.id,
      name: m.tenants.name,
      slug: m.tenants.slug,
      role: m.role,
    }));

    if (tenantId) {
      const membership = (memberships ?? []).find((m: any) => m.tenant_id === tenantId);
      return {
        ...user,
        role: (membership as any)?.role ?? user.role,
        tenant_id: tenantId,
        tenants,
      };
    }

    return { ...user, tenant_id: null, tenants };
  }

  async createTenant(userId: string, dto: { tenant_name: string; tenant_slug?: string }) {
    const slug = dto.tenant_slug ?? generateSlug(dto.tenant_name);

    const { data: existingTenant } = await this.supabase.db
      .from('tenants')
      .select('id')
      .eq('slug', slug)
      .single();

    if (existingTenant) {
      throw new ConflictException({ code: 'SLUG_ALREADY_EXISTS', message: 'Tenant slug already taken' });
    }

    const { data: tenant, error: tenantError } = await this.supabase.db
      .from('tenants')
      .insert({ name: dto.tenant_name, slug })
      .select()
      .single();

    if (tenantError) throw new BadRequestException(tenantError.message);

    await this.supabase.db.from('user_tenants').insert({
      user_id: userId,
      tenant_id: tenant.id,
      role: 'business_owner',
    });

    return { tenant: { id: tenant.id, name: tenant.name, slug: tenant.slug } };
  }

  async updateDeviceToken(userId: string, deviceToken: string | null) {
    await this.supabase.db
      .from('users')
      .update({ device_token: deviceToken })
      .eq('id', userId);
    return { message: 'Device token updated' };
  }
}
