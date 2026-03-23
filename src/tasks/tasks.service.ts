import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service.js';
import { NotificationsService } from '../notifications/notifications.service.js';
import { CreateTaskDto } from './dto/create-task.dto.js';
import { UpdateTaskDto } from './dto/update-task.dto.js';
import { AssignTaskDto } from './dto/assign-task.dto.js';
import { CancelTaskDto } from './dto/cancel-task.dto.js';
import { CheckinDto } from './dto/checkin.dto.js';
import { PaginationDto } from '../common/dto/pagination.dto.js';
import { haversineDistance } from '../common/utils/haversine.util.js';
import { ConfigService } from '@nestjs/config';

interface CurrentUser {
  id: string;
  tenant_id: string;
  role: string;
}

@Injectable()
export class TasksService {
  constructor(
    private supabase: SupabaseService,
    private notifications: NotificationsService,
    private config: ConfigService,
  ) {}

  async createTask(dto: CreateTaskDto, user: CurrentUser) {
    const { assignee_ids, ...taskData } = dto;

    const { data: task, error } = await this.supabase.db
      .from('tasks')
      .insert({
        ...taskData,
        tenant_id: user.tenant_id,
        created_by: user.id,
        location_radius_m: taskData.location_radius_m ?? 100,
        priority: taskData.priority ?? 'medium',
      })
      .select()
      .single();

    if (error) throw new BadRequestException(error.message);

    // Assign users
    if (assignee_ids && assignee_ids.length > 0) {
      const assignments = assignee_ids.map((uid) => ({
        task_id: task.id,
        user_id: uid,
        assigned_by: user.id,
      }));
      await this.supabase.db.from('task_assignments').insert(assignments);
    }

    await this.supabase.db.from('audit_logs').insert({
      tenant_id: user.tenant_id,
      task_id: task.id,
      user_id: user.id,
      action: 'task_created',
      metadata: { title: task.title },
    });

    if (assignee_ids && assignee_ids.length > 0) {
      void this.notifications.sendPushNotification({
        user_ids: assignee_ids,
        type: 'task_assigned',
        title: 'New Task Assigned',
        body: `You have been assigned to: ${task.title}`,
        task_id: task.id,
        tenant_id: user.tenant_id,
      });
    }

    return task;
  }

  async listTasks(user: CurrentUser, pagination: PaginationDto, filters: {
    status?: string;
    priority?: string;
    assignee_id?: string;
    from?: string;
    to?: string;
  }) {
    const { page = 1, limit = 20 } = pagination;
    const offset = (page - 1) * limit;

    let query = this.supabase.db
      .from('tasks')
      .select(`
        *,
        task_assignments(user_id, users!task_assignments_user_id_fkey(id, full_name, avatar_url)),
        creator:created_by(id, full_name)
      `, { count: 'exact' })
      .eq('tenant_id', user.tenant_id);

    if (filters.status) query = query.eq('status', filters.status);
    if (filters.priority) query = query.eq('priority', filters.priority);
    if (filters.from) query = query.gte('created_at', filters.from);
    if (filters.to) query = query.lte('created_at', filters.to);

    const { data, count, error } = await query
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw new BadRequestException(error.message);
    return { data, meta: { total: count, page, limit } };
  }

  async getDashboard(user: CurrentUser, from?: string, to?: string) {
    let query = this.supabase.db
      .from('tasks')
      .select('status, deadline')
      .eq('tenant_id', user.tenant_id);

    if (from) query = query.gte('created_at', from);
    if (to) query = query.lte('created_at', to);

    const { data, error } = await query;
    if (error) throw new BadRequestException(error.message);

    const now = new Date();
    const summary: Record<string, number> = {
      todo: 0,
      in_progress: 0,
      done: 0,
      cancelled: 0,
      rejected: 0,
      overdue: 0,
    };

    for (const task of data ?? []) {
      summary[task.status] = (summary[task.status] ?? 0) + 1;
      if (
        task.deadline &&
        new Date(task.deadline) < now &&
        !['done', 'cancelled', 'rejected'].includes(task.status)
      ) {
        summary.overdue += 1;
      }
    }

    return { summary };
  }

  async getTask(id: string, user: CurrentUser) {
    const { data, error } = await this.supabase.db
      .from('tasks')
      .select(`
        *,
        task_assignments(user_id, users!task_assignments_user_id_fkey(id, full_name, avatar_url)),
        creator:created_by(id, full_name),
        checkins(*)
      `)
      .eq('id', id)
      .eq('tenant_id', user.tenant_id)
      .single();

    if (error || !data) throw new NotFoundException({ code: 'TASK_NOT_FOUND', message: 'Task not found' });
    return data;
  }

  async updateTask(id: string, dto: UpdateTaskDto, user: CurrentUser) {
    const task = await this.getTask(id, user);
    if (['done', 'cancelled', 'rejected'].includes(task.status)) {
      throw new UnprocessableEntityException({ code: 'TASK_ALREADY_CLOSED', message: 'Cannot update a closed task' });
    }

    const { data, error } = await this.supabase.db
      .from('tasks')
      .update(dto)
      .eq('id', id)
      .eq('tenant_id', user.tenant_id)
      .select()
      .single();

    if (error) throw new BadRequestException(error.message);

    await this.supabase.db.from('audit_logs').insert({
      tenant_id: user.tenant_id,
      task_id: id,
      user_id: user.id,
      action: 'task_updated',
      metadata: dto,
    });

    return data;
  }

  async assignTask(id: string, dto: AssignTaskDto, user: CurrentUser) {
    const task = await this.getTask(id, user);

    // Get existing assignees to find new ones
    const { data: existing } = await this.supabase.db
      .from('task_assignments')
      .select('user_id')
      .eq('task_id', id);

    const existingIds = new Set((existing ?? []).map((a) => a.user_id));
    const newAssignees = dto.assignee_ids.filter((uid) => !existingIds.has(uid));

    if (newAssignees.length > 0) {
      const assignments = newAssignees.map((uid) => ({
        task_id: id,
        user_id: uid,
        assigned_by: user.id,
      }));
      await this.supabase.db.from('task_assignments').insert(assignments);
    }

    await this.supabase.db.from('audit_logs').insert({
      tenant_id: user.tenant_id,
      task_id: id,
      user_id: user.id,
      action: 'task_assigned',
      metadata: { assignee_ids: dto.assignee_ids },
    });

    if (newAssignees.length > 0) {
      void this.notifications.sendPushNotification({
        user_ids: newAssignees,
        type: 'task_assigned',
        title: 'New Task Assigned',
        body: `You have been assigned to: ${task.title}`,
        task_id: id,
        tenant_id: user.tenant_id,
      });
    }

    return { message: 'Task assigned', new_assignees: newAssignees.length };
  }

  async unassignTask(taskId: string, staffId: string, user: CurrentUser) {
    await this.getTask(taskId, user);

    await this.supabase.db
      .from('task_assignments')
      .delete()
      .eq('task_id', taskId)
      .eq('user_id', staffId);

    return { message: 'User unassigned from task' };
  }

  async cancelTask(id: string, dto: CancelTaskDto, user: CurrentUser) {
    const task = await this.getTask(id, user);

    if (['done', 'rejected'].includes(task.status)) {
      throw new UnprocessableEntityException({ code: 'CANNOT_CANCEL', message: 'Cannot cancel a done or rejected task' });
    }

    if (task.status === 'cancelled') {
      throw new UnprocessableEntityException({ code: 'ALREADY_CANCELLED', message: 'Task already cancelled' });
    }

    const { data, error } = await this.supabase.db
      .from('tasks')
      .update({
        status: 'cancelled',
        cancel_reason: dto.cancel_reason,
        cancelled_at: new Date().toISOString(),
      })
      .eq('id', id)
      .select()
      .single();

    if (error) throw new BadRequestException(error.message);

    await this.supabase.db.from('audit_logs').insert({
      tenant_id: user.tenant_id,
      task_id: id,
      user_id: user.id,
      action: 'task_cancelled',
      metadata: { cancel_reason: dto.cancel_reason },
    });

    return data;
  }

  async rejectTask(id: string, reason: string | undefined, user: CurrentUser) {
    const task = await this.getTask(id, user);

    if (['done', 'cancelled'].includes(task.status)) {
      throw new UnprocessableEntityException({ code: 'CANNOT_REJECT', message: 'Cannot reject this task' });
    }

    const { data, error } = await this.supabase.db
      .from('tasks')
      .update({ status: 'rejected', cancel_reason: reason })
      .eq('id', id)
      .select()
      .single();

    if (error) throw new BadRequestException(error.message);

    await this.supabase.db.from('audit_logs').insert({
      tenant_id: user.tenant_id,
      task_id: id,
      user_id: user.id,
      action: 'task_rejected',
      metadata: { reason },
    });

    return data;
  }

  async checkin(
    taskId: string,
    dto: CheckinDto,
    file: Express.Multer.File | undefined,
    user: CurrentUser,
    type: 'checkin' | 'checkout',
  ) {
    const task = await this.getTask(taskId, user);

    // Verify user is an assignee
    const { data: assignment } = await this.supabase.db
      .from('task_assignments')
      .select('id')
      .eq('task_id', taskId)
      .eq('user_id', user.id)
      .single();

    if (!assignment) {
      throw new ForbiddenException({ code: 'NOT_ASSIGNEE', message: 'You are not assigned to this task' });
    }

    if (type === 'checkin' && task.status !== 'todo') {
      throw new UnprocessableEntityException({ code: 'TASK_ALREADY_STARTED', message: 'Task is not in todo status' });
    }
    if (type === 'checkout' && task.status !== 'in_progress') {
      throw new UnprocessableEntityException({ code: 'TASK_NOT_IN_PROGRESS', message: 'Task is not in progress' });
    }

    // GPS verification
    let gpsVerified = false;
    if (
      dto.gps_lat !== undefined &&
      dto.gps_lng !== undefined &&
      task.location_lat !== null &&
      task.location_lng !== null
    ) {
      const distance = haversineDistance(dto.gps_lat, dto.gps_lng, task.location_lat, task.location_lng);
      gpsVerified = distance <= task.location_radius_m;
      if (!gpsVerified) {
        throw new BadRequestException({
          code: 'GPS_OUT_OF_RANGE',
          message: `You are ${Math.round(distance)}m away from the task location (max ${task.location_radius_m}m)`,
        });
      }
    }

    // Upload photo
    let photoUrl: string | undefined;
    if (file) {
      const supabaseUrl = this.config.getOrThrow<string>('SUPABASE_URL');
      const filePath = `${user.tenant_id}/${taskId}/${type}/${Date.now()}.${file.originalname.split('.').pop()}`;

      const { data: uploadData, error: uploadError } = await this.supabase.db.storage
        .from('checkin-photos')
        .upload(filePath, file.buffer, {
          contentType: file.mimetype,
          upsert: false,
        });

      if (uploadError) throw new BadRequestException(`Photo upload failed: ${uploadError.message}`);

      const { data: publicData } = this.supabase.db.storage
        .from('checkin-photos')
        .getPublicUrl(uploadData.path);

      photoUrl = publicData.publicUrl;
    }

    // Insert checkin record
    const { data: checkin, error } = await this.supabase.db
      .from('checkins')
      .insert({
        task_id: taskId,
        user_id: user.id,
        type,
        gps_lat: dto.gps_lat,
        gps_lng: dto.gps_lng,
        gps_verified: gpsVerified,
        photo_url: photoUrl,
        notes: dto.notes,
      })
      .select()
      .single();

    if (error) throw new BadRequestException(error.message);

    // Update task status
    const newStatus = type === 'checkin' ? 'in_progress' : 'done';
    await this.supabase.db.from('tasks').update({ status: newStatus }).eq('id', taskId);

    const auditAction = type === 'checkin' ? 'checkin' : 'checkout';
    await this.supabase.db.from('audit_logs').insert({
      tenant_id: user.tenant_id,
      task_id: taskId,
      user_id: user.id,
      action: auditAction,
      metadata: { gps_verified: gpsVerified, photo_url: photoUrl },
    });

    // Notify BO/OT
    const { data: managers } = await this.supabase.db
      .from('user_tenants')
      .select('user_id')
      .eq('tenant_id', user.tenant_id)
      .in('role', ['business_owner', 'operator'])
      .eq('is_active', true);

    const managerIds = (managers ?? []).map((m) => m.user_id);
    if (managerIds.length > 0) {
      const notifType = type === 'checkout' ? 'task_completed' : 'status_changed';
      void this.notifications.sendPushNotification({
        user_ids: managerIds,
        type: notifType,
        title: type === 'checkout' ? 'Task Completed' : 'Task Started',
        body: `${task.title} has been ${type === 'checkout' ? 'completed' : 'started'}`,
        task_id: taskId,
        tenant_id: user.tenant_id,
      });
    }

    return checkin;
  }
}
