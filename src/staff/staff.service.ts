import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ConflictException,
  ForbiddenException,
} from '@nestjs/common';
import * as crypto from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { SupabaseService } from '../supabase/supabase.service.js';
import { EmailService } from '../email/email.service.js';
import { NotificationsService } from '../notifications/notifications.service.js';
import { InviteStaffDto } from './dto/invite-staff.dto.js';
import { RegisterStaffDto } from './dto/register-staff.dto.js';
import { PaginationDto } from '../common/dto/pagination.dto.js';

@Injectable()
export class StaffService {
  constructor(
    private supabase: SupabaseService,
    private jwtService: JwtService,
    private emailService: EmailService,
    private notifications: NotificationsService,
  ) {}

  async invite(dto: InviteStaffDto, invitedBy: { id: string; tenant_id: string }) {
    // Check if user already in this tenant
    const { data: existingMembership } = await this.supabase.db
      .from('user_tenants')
      .select('id, users!inner(id, email)')
      .eq('tenant_id', invitedBy.tenant_id)
      .eq('users.email', dto.email)
      .single();

    if (existingMembership) {
      throw new ConflictException({ code: 'EMAIL_ALREADY_EXISTS', message: 'User with this email already exists in this tenant' });
    }

    // Cancel any pending invitations for this email in this tenant
    await this.supabase.db
      .from('invitations')
      .update({ status: 'cancelled' })
      .eq('email', dto.email)
      .eq('tenant_id', invitedBy.tenant_id)
      .eq('status', 'pending');

    // Check if user already has an account (for in-app invite)
    const { data: existingUser } = await this.supabase.db
      .from('users')
      .select('id')
      .eq('email', dto.email)
      .single();

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const role = dto.role ?? 'staff';

    if (existingUser) {
      // In-app invitation
      const { data, error } = await this.supabase.db
        .from('invitations')
        .insert({
          tenant_id: invitedBy.tenant_id,
          email: dto.email,
          role,
          token,
          invited_by: invitedBy.id,
          expires_at: expiresAt,
          delivery: 'in_app',
          invited_user_id: existingUser.id,
        })
        .select()
        .single();

      if (error) throw new BadRequestException(error.message);

      await this.supabase.db.from('audit_logs').insert({
        tenant_id: invitedBy.tenant_id,
        user_id: invitedBy.id,
        action: 'member_invited',
        metadata: { email: dto.email, role, delivery: 'in_app' },
      });

      void this.notifications.sendPushNotification({
        user_ids: [existingUser.id],
        type: 'invitation_received',
        title: 'New Invitation',
        body: 'You have been invited to join a new tenant',
        tenant_id: invitedBy.tenant_id,
      });

      void this.emailService.sendInvitationAcceptEmail(dto.email, token);

      return { message: 'Invitation sent via push and email', invitation_id: data.id };
    }

    // Email invitation (new user)
    const { data, error } = await this.supabase.db
      .from('invitations')
      .insert({
        tenant_id: invitedBy.tenant_id,
        email: dto.email,
        role,
        token,
        invited_by: invitedBy.id,
        expires_at: expiresAt,
        delivery: 'email',
      })
      .select()
      .single();

    if (error) throw new BadRequestException(error.message);

    await this.supabase.db.from('audit_logs').insert({
      tenant_id: invitedBy.tenant_id,
      user_id: invitedBy.id,
      action: 'member_invited',
      metadata: { email: dto.email, role, delivery: 'email' },
    });

    await this.emailService.sendInvitationEmail(dto.email, token);

    return { message: 'Invitation sent', invitation_id: data.id, token };
  }

  async register(dto: RegisterStaffDto) {
    const { data: invitation, error } = await this.supabase.db
      .from('invitations')
      .select('*')
      .eq('token', dto.token)
      .eq('status', 'pending')
      .eq('delivery', 'email')
      .single();

    if (error || !invitation) {
      throw new BadRequestException({ code: 'INVALID_TOKEN', message: 'Invalid or expired invitation token' });
    }

    if (new Date(invitation.expires_at) < new Date()) {
      await this.supabase.db.from('invitations').update({ status: 'expired' }).eq('id', invitation.id);
      throw new BadRequestException({ code: 'TOKEN_EXPIRED', message: 'Invitation token has expired' });
    }

    // Check email not taken globally
    const { data: existingUser } = await this.supabase.db
      .from('users')
      .select('id')
      .eq('email', invitation.email)
      .single();

    if (existingUser) {
      throw new ConflictException({ code: 'EMAIL_ALREADY_EXISTS', message: 'Email already registered' });
    }

    // Create user in Supabase Auth (trigger auto-creates public.users with role='staff')
    const { data: authData, error: authError } = await this.supabase.db.auth.admin.createUser({
      email: invitation.email,
      password: dto.password,
      email_confirm: true,
      user_metadata: { full_name: dto.full_name },
    });

    if (authError) throw new BadRequestException(authError.message);

    // Update public.users with full_name and phone
    await this.supabase.db
      .from('users')
      .update({ full_name: dto.full_name, phone: dto.phone ?? null })
      .eq('id', authData.user.id);

    // Add user to tenant via user_tenants
    await this.supabase.db.from('user_tenants').insert({
      user_id: authData.user.id,
      tenant_id: invitation.tenant_id,
      role: invitation.role,
    });

    await this.supabase.db
      .from('invitations')
      .update({ status: 'accepted' })
      .eq('id', invitation.id);

    const payload = {
      sub: authData.user.id,
      email: authData.user.email,
      role: invitation.role,
      tenant_id: invitation.tenant_id,
    };

    return {
      access_token: this.jwtService.sign(payload),
      user: {
        id: authData.user.id,
        email: authData.user.email,
        full_name: dto.full_name,
        role: invitation.role,
        tenant_id: invitation.tenant_id,
      },
    };
  }

  async listStaff(tenantId: string, pagination: PaginationDto) {
    const { page = 1, limit = 20 } = pagination;
    const offset = (page - 1) * limit;

    const { data, count, error } = await this.supabase.db
      .from('user_tenants')
      .select(
        'role, is_active, created_at, users!inner(id, email, full_name, phone, avatar_url, last_login_at)',
        { count: 'exact' },
      )
      .eq('tenant_id', tenantId)
      .in('role', ['staff', 'operator'])
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw new BadRequestException(error.message);

    const normalized = (data ?? []).map((row: any) => ({
      id: row.users.id,
      email: row.users.email,
      full_name: row.users.full_name,
      phone: row.users.phone,
      avatar_url: row.users.avatar_url,
      last_login_at: row.users.last_login_at,
      role: row.role,
      is_active: row.is_active,
      created_at: row.created_at,
    }));

    return { data: normalized, meta: { total: count, page, limit } };
  }

  async listInvitations(tenantId: string, pagination: PaginationDto) {
    const { page = 1, limit = 20 } = pagination;
    const offset = (page - 1) * limit;

    const { data, count, error } = await this.supabase.db
      .from('invitations')
      .select('*', { count: 'exact' })
      .eq('tenant_id', tenantId)
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw new BadRequestException(error.message);
    return { data, meta: { total: count, page, limit } };
  }

  async resendInvitation(id: string, currentUser: { id: string; tenant_id: string }) {
    const { data: invitation } = await this.supabase.db
      .from('invitations')
      .select('*')
      .eq('id', id)
      .eq('tenant_id', currentUser.tenant_id)
      .single();

    if (!invitation) throw new NotFoundException({ code: 'INVITATION_NOT_FOUND', message: 'Invitation not found' });

    // Cancel old
    await this.supabase.db.from('invitations').update({ status: 'cancelled' }).eq('id', id);

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    const { data, error } = await this.supabase.db
      .from('invitations')
      .insert({
        tenant_id: invitation.tenant_id,
        email: invitation.email,
        role: invitation.role,
        token,
        invited_by: currentUser.id,
        expires_at: expiresAt,
        delivery: invitation.delivery,
        invited_user_id: invitation.invited_user_id ?? undefined,
      })
      .select()
      .single();

    if (error) throw new BadRequestException(error.message);

    if (invitation.delivery === 'in_app' && invitation.invited_user_id) {
      void this.notifications.sendPushNotification({
        user_ids: [invitation.invited_user_id],
        type: 'invitation_received',
        title: 'New Invitation',
        body: 'You have been invited to join a new tenant',
        tenant_id: currentUser.tenant_id,
      });
    } else {
      await this.emailService.sendInvitationEmail(invitation.email, token);
    }

    return { message: 'Invitation resent', invitation_id: data.id, token: invitation.delivery === 'email' ? token : undefined };
  }

  async removeStaff(staffId: string, currentUser: { id: string; tenant_id: string }) {
    const { data: membership } = await this.supabase.db
      .from('user_tenants')
      .select('id, role')
      .eq('user_id', staffId)
      .eq('tenant_id', currentUser.tenant_id)
      .single();

    if (!membership) throw new NotFoundException({ code: 'USER_NOT_FOUND', message: 'Staff member not found' });
    if (!['staff', 'operator'].includes((membership as any).role)) {
      throw new ForbiddenException({ code: 'FORBIDDEN', message: 'Cannot remove this user' });
    }

    await this.supabase.db
      .from('user_tenants')
      .update({ is_active: false })
      .eq('user_id', staffId)
      .eq('tenant_id', currentUser.tenant_id);

    await this.supabase.db.from('audit_logs').insert({
      tenant_id: currentUser.tenant_id,
      user_id: currentUser.id,
      action: 'member_removed',
      metadata: { removed_user_id: staffId },
    });

    return { message: 'Staff member removed' };
  }

  async getMyInvitations(currentUser: { id: string }) {
    const { data, error } = await this.supabase.db
      .from('invitations')
      .select('id, tenant_id, email, role, delivery, status, expires_at, created_at, tenants(id, name, slug)')
      .eq('invited_user_id', currentUser.id)
      .eq('status', 'pending')
      .order('created_at', { ascending: false });

    if (error) throw new BadRequestException(error.message);
    return data;
  }

  async acceptInvitation(invitationId: string, currentUser: { id: string }) {
    const { data: invitation } = await this.supabase.db
      .from('invitations')
      .select('*')
      .eq('id', invitationId)
      .eq('invited_user_id', currentUser.id)
      .eq('status', 'pending')
      .single();

    if (!invitation) {
      throw new NotFoundException({ code: 'INVITATION_NOT_FOUND', message: 'Invitation not found' });
    }

    if (new Date(invitation.expires_at) < new Date()) {
      await this.supabase.db.from('invitations').update({ status: 'expired' }).eq('id', invitationId);
      throw new BadRequestException({ code: 'TOKEN_EXPIRED', message: 'Invitation has expired' });
    }

    // Add to tenant
    const { error: memberError } = await this.supabase.db
      .from('user_tenants')
      .insert({
        user_id: currentUser.id,
        tenant_id: invitation.tenant_id,
        role: invitation.role,
      });

    if (memberError && !memberError.message.includes('duplicate')) {
      throw new BadRequestException(memberError.message);
    }

    await this.supabase.db
      .from('invitations')
      .update({ status: 'accepted' })
      .eq('id', invitationId);

    return { message: 'Invitation accepted' };
  }

  async acceptInvitationByToken(token: string) {
    const { data: invitation } = await this.supabase.db
      .from('invitations')
      .select('*')
      .eq('token', token)
      .eq('status', 'pending')
      .single();

    if (!invitation) {
      throw new BadRequestException({ code: 'INVALID_TOKEN', message: 'Invalid or expired invitation token' });
    }

    if (new Date(invitation.expires_at) < new Date()) {
      await this.supabase.db.from('invitations').update({ status: 'expired' }).eq('id', invitation.id);
      throw new BadRequestException({ code: 'TOKEN_EXPIRED', message: 'Invitation token has expired' });
    }

    if (!invitation.invited_user_id) {
      throw new BadRequestException({ code: 'INVALID_TOKEN', message: 'Invalid invitation token' });
    }

    const { error: memberError } = await this.supabase.db.from('user_tenants').insert({
      user_id: invitation.invited_user_id,
      tenant_id: invitation.tenant_id,
      role: invitation.role,
    });

    if (memberError && !memberError.message.includes('duplicate')) {
      throw new BadRequestException(memberError.message);
    }

    await this.supabase.db.from('invitations').update({ status: 'accepted' }).eq('id', invitation.id);

    return { message: 'Invitation accepted' };
  }

  async declineInvitation(invitationId: string, currentUser: { id: string }) {
    const { data: invitation } = await this.supabase.db
      .from('invitations')
      .select('id')
      .eq('id', invitationId)
      .eq('invited_user_id', currentUser.id)
      .eq('status', 'pending')
      .single();

    if (!invitation) {
      throw new NotFoundException({ code: 'INVITATION_NOT_FOUND', message: 'Invitation not found' });
    }

    await this.supabase.db
      .from('invitations')
      .update({ status: 'cancelled' })
      .eq('id', invitationId);

    return { message: 'Invitation declined' };
  }
}
