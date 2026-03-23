import { IsString, IsOptional, IsIn, IsNumber, IsDateString } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateTaskDto {
  @IsOptional()
  @IsString()
  title?: string;

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
}
