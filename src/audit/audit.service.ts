import { Injectable, BadRequestException } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service.js';
import { PaginationDto } from '../common/dto/pagination.dto.js';

interface CurrentUser {
  id: string;
  tenant_id: string;
}

@Injectable()
export class AuditService {
  constructor(private supabase: SupabaseService) {}

  async getTaskAuditLogs(taskId: string, user: CurrentUser, pagination: PaginationDto) {
    const { page = 1, limit = 20 } = pagination;
    const offset = (page - 1) * limit;

    const { data, count, error } = await this.supabase.db
      .from('audit_logs')
      .select(`
        *,
        actor:user_id(id, full_name, role)
      `, { count: 'exact' })
      .eq('task_id', taskId)
      .eq('tenant_id', user.tenant_id)
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw new BadRequestException(error.message);
    return { data, meta: { total: count, page, limit } };
  }

  async getStaffAuditLogs(staffId: string, user: CurrentUser, pagination: PaginationDto) {
    const { page = 1, limit = 20 } = pagination;
    const offset = (page - 1) * limit;

    const { data, count, error } = await this.supabase.db
      .from('audit_logs')
      .select(`
        *,
        task:task_id(id, title, status)
      `, { count: 'exact' })
      .eq('user_id', staffId)
      .eq('tenant_id', user.tenant_id)
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw new BadRequestException(error.message);
    return { data, meta: { total: count, page, limit } };
  }

  async getTenantAuditLogs(user: CurrentUser, pagination: PaginationDto, action?: string) {
    const { page = 1, limit = 20 } = pagination;
    const offset = (page - 1) * limit;

    let query = this.supabase.db
      .from('audit_logs')
      .select(`
        *,
        actor:user_id(id, full_name, role),
        task:task_id(id, title)
      `, { count: 'exact' })
      .eq('tenant_id', user.tenant_id);

    if (action) query = query.eq('action', action);

    const { data, count, error } = await query
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw new BadRequestException(error.message);
    return { data, meta: { total: count, page, limit } };
  }
}
