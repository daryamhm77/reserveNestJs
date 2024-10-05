import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { isJWT } from 'class-validator';
import { AuthMessage } from 'src/common/enums/message.enum';
import { AuthService } from '../auth.service';
import { CustomRequest } from 'src/common/interface/user.interface'; 

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const httpcontext = context.switchToHttp();
    const request: CustomRequest = httpcontext.getRequest<CustomRequest>();
    const token = this.extractToken(request);

    
    request.user = await this.authService.validateAccessToken(token); // Assuming this method returns the user data

    return true;
  }

  protected extractToken(request: CustomRequest): string {
    const { authorization } = request.headers;

    if (!authorization || authorization.trim() === '') {
      throw new UnauthorizedException(AuthMessage.LoginIsRequired);
    }

    const [bearer, token] = authorization.split(' ');

    if (bearer?.toLowerCase() !== 'bearer' || !token || !isJWT(token)) {
      throw new UnauthorizedException(AuthMessage.LoginIsRequired);
    }

    return token; 
  }
}
