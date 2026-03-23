import { Controller, Get, Post, Patch, Delete, Body, Param, Query, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { StaffService } from './staff.service.js';
import { InviteStaffDto } from './dto/invite-staff.dto.js';
import { RegisterStaffDto } from './dto/register-staff.dto.js';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard.js';
import { RolesGuard } from '../common/guards/roles.guard.js';
import { Roles } from '../common/decorators/roles.decorator.js';
import { CurrentUser } from '../common/decorators/current-user.decorator.js';
import { PaginationDto } from '../common/dto/pagination.dto.js';

@Controller('staff')
export class StaffController {
  constructor(private readonly staffService: StaffService) {}

  /** Public — register via email invitation token */
  @Post('register')
  register(@Body() dto: RegisterStaffDto) {
    return this.staffService.register(dto);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('business_owner', 'operator', 'superadmin')
  @Post('invite')
  invite(
    @Body() dto: InviteStaffDto,
    @CurrentUser() user: { id: string; tenant_id: string },
  ) {
    return this.staffService.invite(dto, user);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('business_owner', 'operator', 'superadmin')
  @Get()
  listStaff(
    @CurrentUser() user: { tenant_id: string },
    @Query() pagination: PaginationDto,
  ) {
    return this.staffService.listStaff(user.tenant_id, pagination);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('business_owner', 'operator', 'superadmin')
  @Get('invitations')
  listInvitations(
    @CurrentUser() user: { tenant_id: string },
    @Query() pagination: PaginationDto,
  ) {
    return this.staffService.listInvitations(user.tenant_id, pagination);
  }

  /** Must be before :id routes */
  @UseGuards(JwtAuthGuard)
  @Get('my-invitations')
  getMyInvitations(@CurrentUser() user: { id: string }) {
    return this.staffService.getMyInvitations(user);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('business_owner', 'operator', 'superadmin')
  @Post('invite/:id/resend')
  resendInvitation(
    @Param('id') id: string,
    @CurrentUser() user: { id: string; tenant_id: string },
  ) {
    return this.staffService.resendInvitation(id, user);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('invitations/:id/accept')
  acceptInvitation(
    @Param('id') id: string,
    @CurrentUser() user: { id: string },
  ) {
    return this.staffService.acceptInvitation(id, user);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('invitations/:id/decline')
  declineInvitation(
    @Param('id') id: string,
    @CurrentUser() user: { id: string },
  ) {
    return this.staffService.declineInvitation(id, user);
  }

  /** Public — accept invitation via email token link */
  @Patch('accept-invitation/:token')
  acceptInvitationByToken(@Param('token') token: string) {
    return this.staffService.acceptInvitationByToken(token);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('business_owner', 'operator', 'superadmin')
  @Delete(':id')
  removeStaff(
    @Param('id') id: string,
    @CurrentUser() user: { id: string; tenant_id: string },
  ) {
    return this.staffService.removeStaff(id, user);
  }
}
