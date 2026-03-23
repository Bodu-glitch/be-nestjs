import { IsNumber, IsOptional, IsString } from 'class-validator';
import { Type } from 'class-transformer';

export class CheckinDto {
  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  gps_lat?: number;

  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  gps_lng?: number;

  @IsOptional()
  @IsString()
  notes?: string;
}
