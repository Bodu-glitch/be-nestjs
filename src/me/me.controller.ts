import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { MeService } from './me.service.js';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard.js';
import { CurrentUser } from '../common/decorators/current-user.decorator.js';
import { PaginationDto } from '../common/dto/pagination.dto.js';

interface CurrentUserType {
  id: string;
  tenant_id: string;
}

@Controller('me')
@UseGuards(JwtAuthGuard)
export class MeController {
  constructor(private readonly meService: MeService) {}

  /** GET /me/tasks/history — MUST be before /me/tasks */
  @Get('tasks/history')
  getMyTaskHistory(
    @CurrentUser() user: CurrentUserType,
    @Query() pagination: PaginationDto,
  ) {
    return this.meService.getMyTaskHistory(user, pagination);
  }

  @Get('tasks')
  getMyTasks(
    @CurrentUser() user: CurrentUserType,
    @Query() pagination: PaginationDto,
    @Query('status') status?: string,
  ) {
    return this.meService.getMyTasks(user, pagination, status);
  }
}
