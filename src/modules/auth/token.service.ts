import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AccessTokenPayload, CookiePayload } from './types/payload';
import { AuthMessage } from 'src/common/enums/message.enum';

@Injectable()
export class TokenService {
  constructor(private jwtService: JwtService) {}

  createToken(payload: CookiePayload) {
    const token = this.jwtService.sign(payload, {
      secret: process.env.OTP_TOKEN,
      expiresIn: 60 * 2, 
    });
    return token;
  }

  verifyToken(token: string): CookiePayload {
    try {
      return this.jwtService.verify(token, {
        secret: process.env.OTP_TOKEN_SECRET,
      });
    } catch (error) {
      
      throw new UnauthorizedException(AuthMessage.TryAgain);
    }
  }

  createAccessToken(payload: AccessTokenPayload) {
    return this.jwtService.sign(payload, {
      secret: process.env.ACCESS_TOKEN,
      expiresIn: '1y', 
    });
  }

  verifyAccessToken(token: string): { userId: any } {
    try {
      return this.jwtService.verify(token, {
        secret: process.env.ACCESS_TOKEN,
      });
    } catch (error) {
      
      throw new UnauthorizedException(AuthMessage.LoginAgain);
    }
  }
}
