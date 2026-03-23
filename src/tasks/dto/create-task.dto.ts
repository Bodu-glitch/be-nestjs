import { IsString, IsNotEmpty, IsOptional, IsIn, IsNumber, IsArray, IsUUID, IsDateString } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateTaskDto {
  @IsString()
  @IsNotEmpty()
  title: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsIn(['low', 'medium', 'high', 'urgent'])
  priority?: string;

  @IsOptional()
  @IsString()
  location_name?: string;

  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  location_lat?: number;

  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  location_lng?: number;

  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  location_radius_m?: number;

  @IsOptional()
  @IsDateString()
  scheduled_at?: string;

  @IsOptional()
  @IsDateString()
  deadline?: string;

  @IsOptional()
  @IsArray()
  @IsUUID(undefined, { each: true })
  assignee_ids?: string[];
}
