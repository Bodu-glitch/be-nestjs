import { IsArray, IsUUID } from 'class-validator';

export class AssignTaskDto {
  @IsArray()
  @IsUUID(undefined, { each: true })
  assignee_ids: string[];
}
