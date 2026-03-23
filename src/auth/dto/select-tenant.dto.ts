import { IsUUID, IsNotEmpty } from 'class-validator';

export class SelectTenantDto {
  @IsUUID()
  @IsNotEmpty()
  user_id: string;

  @IsUUID()
  @IsNotEmpty()
  tenant_id: string;
}
