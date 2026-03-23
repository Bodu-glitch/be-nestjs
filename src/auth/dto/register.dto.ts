import { IsEmail, IsString, MinLength, IsNotEmpty, IsOptional, Matches } from 'class-validator';

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  password: string;

  @IsString()
  @IsNotEmpty()
  full_name: string;

  @IsString()
  @IsNotEmpty()
  tenant_name: string;

  @IsString()
  @IsOptional()
  @Matches(/^[a-z0-9-]+$/, { message: 'tenant_slug must contain only lowercase letters, numbers, and hyphens' })
  tenant_slug?: string;
}
