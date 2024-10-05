import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  Scope,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { isEmail, isMobilePhone } from 'class-validator';
import { Repository } from 'typeorm';
import { UserEntity } from '../user/entities/user.entity';
import { AuthDto } from './dto/auth.dto';
import { AuthMethod } from './enums/method.enum';
import { AuthType } from './enums/type.enum';
import { ResTypes } from './types/response';
import { OtpEntity } from '../user/entities/otp.entity';
import { REQUEST } from '@nestjs/core';
import { TokenService } from './token.service';
import {
  AuthMessage,
  BadRequestMessage,
  PublicMessage,
} from 'src/common/enums/message.enum';
import { randomInt } from 'crypto';
import { CookieKeys } from './enums/cookie.enum';
import { Response } from 'express';
import { CustomRequest } from 'src/common/interface/user.interface';
import { CustomRequestCookies } from 'src/common/interface/cookie.interface';

@Injectable({ scope: Scope.REQUEST })
export class AuthService {
  verifyOtp(code: string) {
    throw new Error('Method not implemented.');
  }
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
    @InjectRepository(OtpEntity)
    private otpRepository: Repository<OtpEntity>,
    @Inject(REQUEST) private request: Request,
    private tokenService: TokenService,
  ) {}

  async userExists(authDto: AuthDto, res: Response) {
    const { method, type, username } = authDto;
    let result: ResTypes;

    switch (type) {
      case AuthType.Register:
        result = await this.register(method, username);
        return this.sendResponse(res, result);
      case AuthType.Login:
        result = await this.login(method, username);
        return this.sendResponse(res, result);
    }
    return authDto;
  }

  async register(method: AuthMethod, username: string) {
    const userValid = this.usernameValidator(method, username);
    let user: UserEntity = await this.checkExistedUser(method, userValid);
    if (user) throw new ConflictException(AuthMessage.NotFoundAccount);

    user = this.userRepository.create({
      [method]: username,
    });
    user = await this.userRepository.save(user);
    user.username = `m_${user.id}`;
    user = await this.userRepository.save(user);

    const otp = await this.saveOtp(user.id);
    otp.method = method;
    await this.otpRepository.save(otp);

    const token = this.tokenService.createToken({ userId: user.id });
    return {
      token,
      code: otp.code,
    };
  }

  async login(method: AuthMethod, username: string) {
    const userValid = this.usernameValidator(method, username);
    const user: UserEntity = await this.checkExistedUser(method, userValid);
    if (!user) throw new UnauthorizedException(AuthMessage.NotFoundAccount);

    const otp = await this.saveOtp(user.id);
    const token = this.tokenService.createToken({ userId: user.id });

    return {
      code: otp.code,
      token,
    };
  }

  async checkExistedUser(method: AuthMethod, username: string) {
    let user: UserEntity;

    if (method === AuthMethod.Phone) {
      user = await this.userRepository.findOneBy({ phone: username });
    } else if (method === AuthMethod.Email) {
      user = await this.userRepository.findOneBy({ email: username });
    } else if (method === AuthMethod.Username) {
      user = await this.userRepository.findOneBy({ username });
    } else {
      throw new BadRequestException(BadRequestMessage.InValidLoginData);
    }

    return user;
  }

  usernameValidator(method: AuthMethod, username: string) {
    switch (method) {
      case AuthMethod.Email:
        if (isEmail(username)) return username;
        throw new BadRequestException('Email is not correct!');
      case AuthMethod.Phone:
        if (isMobilePhone(username, 'fa-IR')) return username;
        throw new BadRequestException('Phone Number is Not Correct!');
      case AuthMethod.Username:
        return username;
      default:
        throw new UnauthorizedException('Username data is not valid!');
    }
  }

  async saveOtp(userId: number) {
    const code = randomInt(10000, 99999).toString();
    const expiresIn = new Date(Date.now() + 1000 * 60 * 2);

    let otp = await this.otpRepository.findOneBy({ userId });
    let otpExist = false;

    if (otp) {
      otpExist = true;
      otp.code = code;
      otp.expiresIn = expiresIn;
    } else {
      otp = this.otpRepository.create({
        code,
        expiresIn,
        userId,
      });
    }

    otp = await this.otpRepository.save(otp);

    if (!otpExist) {
      await this.userRepository.update({ id: userId }, { otpId: otp.id });
    }

    return otp;
  }

  async sendResponse(res: Response, result: ResTypes) {
    const { token, code } = result;

    res.cookie(CookieKeys.POC, token, {
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 60 * 2),
    });

    res.json({
      message: PublicMessage.SentOtp,
      code,
    });
  }

  async checkOtp(code: string) {
    const request: CustomRequest = this
      .request as unknown as CustomRequestCookies;
    const token = request.cookies?.[CookieKeys.POC]; // Access cookies safely
    if (!token) throw new UnauthorizedException(AuthMessage.ExpiredCode);

    const { userId: userIdString } = this.tokenService.verifyToken(token);
    const userId = Number(userIdString); // Ensure userId is a number

    if (isNaN(userId)) {
      throw new UnauthorizedException('Invalid user ID'); // Handle invalid userId
    }

    const otp = await this.otpRepository.findOneBy({ userId });
    if (!otp) throw new UnauthorizedException(AuthMessage.LoginAgain);

    const now = new Date();
    if (otp.expiresIn < now)
      throw new UnauthorizedException(AuthMessage.ExpiredCode);
    if (code !== otp.code)
      throw new UnauthorizedException(AuthMessage.TryAgain);

    const accessToken = this.tokenService.createAccessToken({ userId });

    if (otp.method === AuthMethod.Email) {
      await this.userRepository.update({ id: userId }, { verify_email: true });
    } else if (otp.method === AuthMethod.Phone) {
      await this.userRepository.update({ id: userId }, { verify_phone: true });
    }
  }

  async validateAccessToken(token: string) {
    const { userId } = this.tokenService.verifyAccessToken(token);
    const user = await this.userRepository.findOneBy({ id: userId });
    if (!user) throw new UnauthorizedException(AuthMessage.LoginAgain);

    return user;
  }
}
