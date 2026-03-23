import { Controller, Get, Param, Query, UseGuards } from '@nestjs/common';
import { AuditService } from './audit.service.js';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard.js';
import { RolesGuard } from '../common/guards/roles.guard.js';
import { Roles } from '../common/decorators/roles.decorator.js';
import { CurrentUser } from '../common/decorators/current-user.decorator.js';
import { PaginationDto } from '../common/dto/pagination.dto.js';

interface CurrentUserType {
  id: string;
  tenant_id: string;
}

@Controller('audit')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('business_owner', 'operator', 'superadmin')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get('tasks/:id')
  getTaskAuditLogs(
    @Param('id') id: string,
    @CurrentUser() user: CurrentUserType,
    @Query() pagination: PaginationDto,
  ) {
    return this.auditService.getTaskAuditLogs(id, user, pagination);
  }

  @Get('staff/:id')
  getStaffAuditLogs(
    @Param('id') id: string,
    @CurrentUser() user: CurrentUserType,
    @Query() pagination: PaginationDto,
  ) {
    return this.auditService.getStaffAuditLogs(id, user, pagination);
  }

  @Get()
  getTenantAuditLogs(
    @CurrentUser() user: CurrentUserType,
    @Query() pagination: PaginationDto,
    @Query('action') action?: string,
  ) {
    return this.auditService.getTenantAuditLogs(user, pagination, action);
  }
}
