import { IsEmail, IsString, MinLength, IsOptional } from 'class-validator';

export class ForgotPasswordDto {
  @IsEmail()
  email: string;
}

export class ResetPasswordDto {
  @IsEmail()
  email: string;

  @IsString()
  otp: string;

  @IsString()
  @MinLength(6)
  new_password: string;

  @IsString()
  @MinLength(6)
  confirm_password: string;
}

export class UpdateDeviceTokenDto {
  @IsString()
  @IsOptional()
  device_token: string | null;
}
