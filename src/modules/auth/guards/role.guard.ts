import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { CustomRequest } from 'src/common/interface/user.interface';
import { ROLE_KEY } from '../../../common/decorators/role.decorator';
import { Roles } from 'src/common/enums/role.enum';

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Roles[]>(ROLE_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles || requiredRoles.length === 0) return true;

    const request: CustomRequest = context
      .switchToHttp()
      .getRequest<CustomRequest>();
    const user = request.user;

    const userRole = user?.role ?? Roles.User;

    if (user.role === Roles.Admin) return true;
    if (requiredRoles.includes(userRole as Roles)) return true;

    throw new ForbiddenException();
  }
}
