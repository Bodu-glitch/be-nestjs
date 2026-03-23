import { IsString, IsNotEmpty, IsOptional, IsObject } from 'class-validator';

export class CreateTenantDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsNotEmpty()
  slug: string;

  @IsOptional()
  @IsObject()
  settings?: Record<string, unknown>;
}
