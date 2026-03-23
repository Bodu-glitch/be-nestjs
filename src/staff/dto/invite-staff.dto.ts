import { IsEmail, IsOptional, IsIn } from 'class-validator';

export class InviteStaffDto {
  @IsEmail()
  email: string;

  @IsOptional()
  @IsIn(['staff', 'operator'])
  role?: string;
}
