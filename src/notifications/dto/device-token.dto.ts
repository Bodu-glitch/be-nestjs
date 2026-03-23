import { IsString } from 'class-validator';

export class DeviceTokenDto {
  @IsString()
  device_token: string;
}
