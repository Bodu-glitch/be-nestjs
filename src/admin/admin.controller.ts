import {
  Controller, Get, Post, Patch, Delete, Body, Param, Query, UseGuards,
} from '@nestjs/common';
import { AdminService } from './admin.service.js';
import { CreateTenantDto } from './dto/create-tenant.dto.js';
import { UpdateTenantDto } from './dto/update-tenant.dto.js';
import { CreateBusinessOwnerDto } from './dto/create-business-owner.dto.js';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard.js';
import { RolesGuard } from '../common/guards/roles.guard.js';
import { Roles } from '../common/decorators/roles.decorator.js';
import { PaginationDto } from '../common/dto/pagination.dto.js';

@Controller('admin')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('superadmin')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  // ── Tenants ──────────────────────────────────────────────────────────────
  @Get('tenants')
  listTenants(@Query() pagination: PaginationDto, @Query('status') status?: string) {
    return this.adminService.listTenants(pagination, status);
  }

  @Get('tenants/:id')
  getTenant(@Param('id') id: string) {
    return this.adminService.getTenant(id);
  }

  @Post('tenants')
  createTenant(@Body() dto: CreateTenantDto) {
    return this.adminService.createTenant(dto);
  }

  @Patch('tenants/:id')
  updateTenant(@Param('id') id: string, @Body() dto: UpdateTenantDto) {
    return this.adminService.updateTenant(id, dto);
  }

  @Delete('tenants/:id')
  deleteTenant(@Param('id') id: string) {
    return this.adminService.deleteTenant(id);
  }

  // ── Users ─────────────────────────────────────────────────────────────────
  @Get('users')
  listUsers(@Query() pagination: PaginationDto, @Query('tenant_id') tenantId?: string) {
    return this.adminService.listUsers(pagination, tenantId);
  }

  @Get('users/:id')
  getUser(@Param('id') id: string) {
    return this.adminService.getUser(id);
  }

  @Post('users')
  createUser(@Body() dto: CreateBusinessOwnerDto) {
    return this.adminService.createUser(dto);
  }

  @Patch('users/:id/activate')
  activateUser(@Param('id') id: string) {
    return this.adminService.toggleUserActive(id, true);
  }

  @Patch('users/:id/deactivate')
  deactivateUser(@Param('id') id: string) {
    return this.adminService.toggleUserActive(id, false);
  }
}
