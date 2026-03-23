import { Injectable, ConflictException, NotFoundException, BadRequestException } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service.js';
import { CreateTenantDto } from './dto/create-tenant.dto.js';
import { UpdateTenantDto } from './dto/update-tenant.dto.js';
import { CreateBusinessOwnerDto } from './dto/create-business-owner.dto.js';
import { PaginationDto } from '../common/dto/pagination.dto.js';

@Injectable()
export class AdminService {
  constructor(private supabase: SupabaseService) {}

  async listTenants(pagination: PaginationDto, status?: string) {
    const { page = 1, limit = 20 } = pagination;
    const offset = (page - 1) * limit;

    let query = this.supabase.db
      .from('tenants')
      .select('*', { count: 'exact' });

    if (status) query = query.eq('status', status);

    const { data, count, error } = await query
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw new BadRequestException(error.message);
    return { data, meta: { total: count, page, limit } };
  }

  async getTenant(id: string) {
    const { data, error } = await this.supabase.db
      .from('tenants')
      .select('*')
      .eq('id', id)
      .single();

    if (error || !data) throw new NotFoundException({ code: 'TENANT_NOT_FOUND', message: 'Tenant not found' });
    return data;
  }

  async createTenant(dto: CreateTenantDto) {
    const { data: existing } = await this.supabase.db
      .from('tenants')
      .select('id')
      .eq('slug', dto.slug)
      .single();

    if (existing) throw new ConflictException({ code: 'SLUG_ALREADY_EXISTS', message: 'Slug already in use' });

    const { data, error } = await this.supabase.db
      .from('tenants')
      .insert({ name: dto.name, slug: dto.slug, settings: dto.settings ?? {} })
      .select()
      .single();

    if (error) throw new BadRequestException(error.message);
    return data;
  }

  async updateTenant(id: string, dto: UpdateTenantDto) {
    await this.getTenant(id);
    const { data, error } = await this.supabase.db
      .from('tenants')
      .update(dto)
      .eq('id', id)
      .select()
      .single();

    if (error) throw new BadRequestException(error.message);
    return data;
  }

  async deleteTenant(id: string) {
    await this.getTenant(id);
    await this.supabase.db.from('tenants').update({ status: 'inactive' }).eq('id', id);
    return { message: 'Tenant deactivated' };
  }

  async listUsers(pagination: PaginationDto, tenantId?: string) {
    const { page = 1, limit = 20 } = pagination;
    const offset = (page - 1) * limit;

    if (tenantId) {
      const { data, count, error } = await this.supabase.db
        .from('user_tenants')
        .select(
          'role, is_active, created_at, users!inner(id, email, full_name, is_active, last_login_at, created_at)',
          { count: 'exact' },
        )
        .eq('tenant_id', tenantId)
        .order('created_at', { ascending: false })
        .range(offset, offset + limit - 1);

      if (error) throw new BadRequestException(error.message);

      const normalized = (data ?? []).map((row: any) => ({
        id: row.users.id,
        email: row.users.email,
        full_name: row.users.full_name,
        role: row.role,
        tenant_id: tenantId,
        is_active: row.is_active,
        last_login_at: row.users.last_login_at,
        created_at: row.users.created_at,
      }));

      return { data: normalized, meta: { total: count, page, limit } };
    }

    const { data, count, error } = await this.supabase.db
      .from('users')
      .select('id, email, full_name, role, is_active, last_login_at, created_at', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw new BadRequestException(error.message);
    return { data, meta: { total: count, page, limit } };
  }

  async createUser(dto: CreateBusinessOwnerDto) {
    // Verify tenant exists
    const { data: tenant } = await this.supabase.db
      .from('tenants')
      .select('id')
      .eq('id', dto.tenant_id)
      .single();

    if (!tenant) throw new NotFoundException({ code: 'TENANT_NOT_FOUND', message: 'Tenant not found' });

    // Create user in Supabase Auth (trigger auto-creates public.users with role='staff')
    const { data: authData, error } = await this.supabase.db.auth.admin.createUser({
      email: dto.email,
      password: dto.password,
      email_confirm: true,
      user_metadata: { full_name: dto.full_name },
    });

    if (error) {
      if (error.message.includes('already')) {
        throw new ConflictException({ code: 'EMAIL_ALREADY_EXISTS', message: 'Email already exists' });
      }
      throw new BadRequestException(error.message);
    }

    // Update public.users with correct full_name and phone (trigger set role='staff')
    await this.supabase.db
      .from('users')
      .update({ full_name: dto.full_name, phone: dto.phone ?? null })
      .eq('id', authData.user.id);

    const role = dto.role ?? 'business_owner';
    const { error: memberError } = await this.supabase.db
      .from('user_tenants')
      .insert({
        user_id: authData.user.id,
        tenant_id: dto.tenant_id,
        role,
      });

    if (memberError) throw new BadRequestException(memberError.message);

    return {
      id: authData.user.id,
      email: authData.user.email,
      full_name: dto.full_name,
      role,
      tenant_id: dto.tenant_id,
    };
  }

  async getUser(id: string) {
    const { data, error } = await this.supabase.db
      .from('users')
      .select('id, email, full_name, role, phone, avatar_url, is_active, last_login_at, created_at, user_tenants(tenant_id, role)')
      .eq('id', id)
      .single();

    if (error || !data) throw new NotFoundException({ code: 'USER_NOT_FOUND', message: 'User not found' });
    return data;
  }

  async toggleUserActive(id: string, isActive: boolean) {
    await this.getUser(id);
    await this.supabase.db.from('users').update({ is_active: isActive }).eq('id', id);
    return { message: `User ${isActive ? 'activated' : 'deactivated'}` };
  }
}
