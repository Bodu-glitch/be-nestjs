import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { SupabaseService } from '../../supabase/supabase.service.js';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private supabase: SupabaseService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) throw new UnauthorizedException();

    const { data: { user }, error } = await this.supabase.db.auth.getUser(token);
    if (error || !user) throw new UnauthorizedException();

    const { data: dbUser } = await this.supabase.db
      .from('users')
      .select('role, is_active')
      .eq('id', user.id)
      .single();

    if (!dbUser?.is_active) throw new UnauthorizedException();

    if (dbUser.role === 'superadmin') {
      req.user = { id: user.id, email: user.email, role: 'superadmin', tenant_id: null };
      return true;
    }

    const tenantId: string | null = req.headers['x-tenant-id'] ?? null;
    if (tenantId) {
      const { data: membership } = await this.supabase.db
        .from('user_tenants')
        .select('role')
        .eq('user_id', user.id)
        .eq('tenant_id', tenantId)
        .eq('is_active', true)
        .single();

      if (!membership) throw new UnauthorizedException();
      req.user = { id: user.id, email: user.email, role: (membership as any).role, tenant_id: tenantId };
    } else {
      req.user = { id: user.id, email: user.email, role: null, tenant_id: null };
    }

    return true;
  }
}
