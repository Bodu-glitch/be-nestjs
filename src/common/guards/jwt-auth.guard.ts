import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest();
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) throw new UnauthorizedException();
    try {
      const payload = this.jwtService.verify(token);
      req.user = {
        id: payload.sub,
        email: payload.email,
        role: payload.role,
        tenant_id: payload.tenant_id,
      };
      return true;
    } catch {
      throw new UnauthorizedException();
    }
  }
}
