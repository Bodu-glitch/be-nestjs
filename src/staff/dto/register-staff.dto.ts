import { IsString, IsNotEmpty, MinLength, IsOptional } from 'class-validator';

export class RegisterStaffDto {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsString()
  @IsNotEmpty()
  full_name: string;

  @IsString()
  @MinLength(6)
  password: string;

  @IsOptional()
  @IsString()
  phone?: string;
}
