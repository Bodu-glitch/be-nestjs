import { IsString, IsNotEmpty, IsOptional, Matches } from 'class-validator';

export class CreateTenantDto {
  @IsString()
  @IsNotEmpty()
  tenant_name: string;

  @IsString()
  @IsOptional()
  @Matches(/^[a-z0-9-]+$/, { message: 'tenant_slug must contain only lowercase letters, numbers, and hyphens' })
  tenant_slug?: string;
}
