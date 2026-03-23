import { Injectable, BadRequestException } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service.js';
import { PaginationDto } from '../common/dto/pagination.dto.js';

interface CurrentUser {
  id: string;
  tenant_id: string;
}

@Injectable()
export class MeService {
  constructor(private supabase: SupabaseService) {}

  async getMyTasks(user: CurrentUser, pagination: PaginationDto, status?: string) {
    const { page = 1, limit = 20 } = pagination;
    const offset = (page - 1) * limit;

    let query = this.supabase.db
      .from('task_assignments')
      .select(`
        task_id,
        tasks(
          id, title, description, status, priority,
          location_name, location_lat, location_lng, location_radius_m,
          scheduled_at, deadline, created_at, updated_at,
          creator:created_by(id, full_name)
        )
      `, { count: 'exact' })
      .eq('user_id', user.id);

    if (status) {
      query = query.eq('tasks.status', status);
    }

    const { data, count, error } = await query
      .order('assigned_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw new BadRequestException(error.message);

    // Flatten: extract the nested tasks
    const tasks = (data ?? []).map((row: any) => row.tasks).filter(Boolean);
    return { data: tasks, meta: { total: count, page, limit } };
  }

  async getMyTaskHistory(user: CurrentUser, pagination: PaginationDto) {
    const { page = 1, limit = 20 } = pagination;
    const offset = (page - 1) * limit;

    const { data, count, error } = await this.supabase.db
      .from('task_assignments')
      .select(`
        task_id,
        assigned_at,
        tasks(
          id, title, status, priority, deadline, created_at,
          checkins(type, created_at, gps_verified, photo_url)
        )
      `, { count: 'exact' })
      .eq('user_id', user.id)
      .in('tasks.status', ['done', 'cancelled', 'rejected'])
      .order('assigned_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw new BadRequestException(error.message);
    const tasks = (data ?? []).map((row: any) => row.tasks).filter(Boolean);
    return { data: tasks, meta: { total: count, page, limit } };
  }
}
