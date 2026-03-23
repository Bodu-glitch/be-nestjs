import { IsString, IsOptional, IsIn, IsObject } from 'class-validator';

export class UpdateTenantDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  slug?: string;

  @IsOptional()
  @IsIn(['active', 'inactive', 'suspended'])
  status?: string;

  @IsOptional()
  @IsObject()
  settings?: Record<string, unknown>;
}
