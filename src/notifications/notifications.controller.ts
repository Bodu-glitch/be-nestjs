import { Controller, Get, Patch, Param, Query, UseGuards } from '@nestjs/common';
import { NotificationsService } from './notifications.service.js';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard.js';
import { CurrentUser } from '../common/decorators/current-user.decorator.js';
import { PaginationDto } from '../common/dto/pagination.dto.js';

interface CurrentUserType {
  id: string;
  tenant_id: string;
}

@Controller('notifications')
@UseGuards(JwtAuthGuard)
export class NotificationsController {
  constructor(private readonly notificationsService: NotificationsService) {}

  @Get()
  list(@CurrentUser() user: CurrentUserType, @Query() pagination: PaginationDto) {
    return this.notificationsService.listNotifications(user.id, user.tenant_id, pagination);
  }

  @Get('unread-count')
  unreadCount(@CurrentUser() user: CurrentUserType) {
    return this.notificationsService.getUnreadCount(user.id, user.tenant_id);
  }

  @Patch('read-all')
  markAllRead(@CurrentUser() user: CurrentUserType) {
    return this.notificationsService.markAllRead(user.id, user.tenant_id);
  }

  @Patch(':id/read')
  markRead(@Param('id') id: string, @CurrentUser() user: CurrentUserType) {
    return this.notificationsService.markRead(id, user.id);
  }
}
