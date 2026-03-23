import { IsString, IsOptional } from 'class-validator';

export class GoogleAuthDto {
  @IsString()
  id_token: string;

  @IsString()
  @IsOptional()
  access_token?: string;
}
