import { IsString, IsOptional } from 'class-validator';

export class CancelTaskDto {
  @IsOptional()
  @IsString()
  cancel_reason?: string;
}
