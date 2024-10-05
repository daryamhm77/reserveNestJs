import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SwaggerConsumes } from 'src/common/enums/swagger.consumes.enum';
import { ApiBearerAuth, ApiConsumes } from '@nestjs/swagger';
import { AuthDto, CheckOtp } from './dto/auth.dto';
import { AuthGuard } from './guards/auth.guard';
import { CanAccess } from 'src/common/decorators/role.decorator';
import { Roles } from 'src/common/enums/role.enum';
import { Request, Response } from 'express';
import { CustomRequest } from 'src/common/interface/user.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('user-exists')
  @ApiConsumes(SwaggerConsumes.UrlEncoded, SwaggerConsumes.Json)
  userExistence(@Body() authDto: AuthDto, @Res() res: Response) {
    return this.authService.userExists(authDto, res);
  }

  @Post('check-otp')
  @ApiConsumes(SwaggerConsumes.UrlEncoded, SwaggerConsumes.Json)
  checkOtp(@Body() checkDto: CheckOtp) {
    return this.authService.verifyOtp(checkDto.code); 
  }

  @Get('check-login')
  @ApiBearerAuth('AUTHORIZATION')
  @UseGuards(AuthGuard)
  @CanAccess(Roles.Admin)
  checkLogin(@Req() req: CustomRequest) {
    return req.user;
  }
}
