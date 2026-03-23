import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module.js';
import { TasksController } from './tasks.controller.js';
import { TasksService } from './tasks.service.js';
import { NotificationsModule } from '../notifications/notifications.module.js';

@Module({
  imports: [AuthModule, NotificationsModule],
  controllers: [TasksController],
  providers: [TasksService],
})
export class TasksModule {}
