import {
  Controller, Get, Post, Patch, Delete, Body, Param, Query,
  UseGuards, UseInterceptors, UploadedFile,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { TasksService } from './tasks.service.js';
import { CreateTaskDto } from './dto/create-task.dto.js';
import { UpdateTaskDto } from './dto/update-task.dto.js';
import { AssignTaskDto } from './dto/assign-task.dto.js';
import { CancelTaskDto } from './dto/cancel-task.dto.js';
import { CheckinDto } from './dto/checkin.dto.js';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard.js';
import { RolesGuard } from '../common/guards/roles.guard.js';
import { Roles } from '../common/decorators/roles.decorator.js';
import { CurrentUser } from '../common/decorators/current-user.decorator.js';
import { PaginationDto } from '../common/dto/pagination.dto.js';

interface CurrentUserType {
  id: string;
  tenant_id: string;
  role: string;
}

@Controller('tasks')
@UseGuards(JwtAuthGuard)
export class TasksController {
  constructor(private readonly tasksService: TasksService) {}

  /** GET /tasks/dashboard — MUST be before /:id */
  @Get('dashboard')
  @UseGuards(RolesGuard)
  @Roles('business_owner', 'operator', 'superadmin')
  getDashboard(
    @CurrentUser() user: CurrentUserType,
    @Query('from') from?: string,
    @Query('to') to?: string,
  ) {
    return this.tasksService.getDashboard(user, from, to);
  }

  @Get()
  listTasks(
    @CurrentUser() user: CurrentUserType,
    @Query() pagination: PaginationDto,
    @Query('status') status?: string,
    @Query('priority') priority?: string,
    @Query('assignee_id') assignee_id?: string,
    @Query('from') from?: string,
    @Query('to') to?: string,
  ) {
    return this.tasksService.listTasks(user, pagination, { status, priority, assignee_id, from, to });
  }

  @Post()
  @UseGuards(RolesGuard)
  @Roles('business_owner', 'operator', 'superadmin')
  createTask(@Body() dto: CreateTaskDto, @CurrentUser() user: CurrentUserType) {
    return this.tasksService.createTask(dto, user);
  }

  @Get(':id')
  getTask(@Param('id') id: string, @CurrentUser() user: CurrentUserType) {
    return this.tasksService.getTask(id, user);
  }

  @Patch(':id')
  @UseGuards(RolesGuard)
  @Roles('business_owner', 'operator', 'superadmin')
  updateTask(
    @Param('id') id: string,
    @Body() dto: UpdateTaskDto,
    @CurrentUser() user: CurrentUserType,
  ) {
    return this.tasksService.updateTask(id, dto, user);
  }

  @Post(':id/assign')
  @UseGuards(RolesGuard)
  @Roles('business_owner', 'operator', 'superadmin')
  assignTask(
    @Param('id') id: string,
    @Body() dto: AssignTaskDto,
    @CurrentUser() user: CurrentUserType,
  ) {
    return this.tasksService.assignTask(id, dto, user);
  }

  @Delete(':id/assign/:staffId')
  @UseGuards(RolesGuard)
  @Roles('business_owner', 'operator', 'superadmin')
  unassignTask(
    @Param('id') id: string,
    @Param('staffId') staffId: string,
    @CurrentUser() user: CurrentUserType,
  ) {
    return this.tasksService.unassignTask(id, staffId, user);
  }

  @Patch(':id/cancel')
  @UseGuards(RolesGuard)
  @Roles('business_owner', 'operator', 'superadmin')
  cancelTask(
    @Param('id') id: string,
    @Body() dto: CancelTaskDto,
    @CurrentUser() user: CurrentUserType,
  ) {
    return this.tasksService.cancelTask(id, dto, user);
  }

  @Patch(':id/reject')
  @UseGuards(RolesGuard)
  @Roles('business_owner', 'operator', 'superadmin')
  rejectTask(
    @Param('id') id: string,
    @Body() body: { reason?: string },
    @CurrentUser() user: CurrentUserType,
  ) {
    return this.tasksService.rejectTask(id, body.reason, user);
  }

  @Post(':id/checkin')
  @UseInterceptors(FileInterceptor('photo', { storage: memoryStorage() }))
  checkin(
    @Param('id') id: string,
    @Body() dto: CheckinDto,
    @UploadedFile() file: Express.Multer.File | undefined,
    @CurrentUser() user: CurrentUserType,
  ) {
    return this.tasksService.checkin(id, dto, file, user, 'checkin');
  }

  @Post(':id/checkout')
  @UseInterceptors(FileInterceptor('photo', { storage: memoryStorage() }))
  checkout(
    @Param('id') id: string,
    @Body() dto: CheckinDto,
    @UploadedFile() file: Express.Multer.File | undefined,
    @CurrentUser() user: CurrentUserType,
  ) {
    return this.tasksService.checkin(id, dto, file, user, 'checkout');
  }
}
