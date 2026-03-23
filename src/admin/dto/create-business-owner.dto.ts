import { IsEmail, IsString, IsNotEmpty, IsUUID, IsOptional, IsIn } from 'class-validator';

export class CreateBusinessOwnerDto {
  @IsUUID()
  tenant_id: string;

  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  full_name: string;

  @IsOptional()
  @IsIn(['business_owner', 'operator'])
  role?: string;

  @IsOptional()
  @IsString()
  phone?: string;
}
