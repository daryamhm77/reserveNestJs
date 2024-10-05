/* eslint-disable prettier/prettier */
import { ApiProperty } from "@nestjs/swagger";
import { IsEnum, isEnum, IsString, Length } from "class-validator";
import { AuthType } from "../enums/type.enum";
import { AuthMethod } from "../enums/method.enum";



export class AuthDto {
  @ApiProperty()
  @Length(5, 100)
  username: string;
  @ApiProperty({enum:AuthType})
  @IsEnum(AuthType)
  type: string;
  @IsEnum(AuthMethod)
  @ApiProperty({enum:AuthMethod})
  method: AuthMethod
}
export class CheckOtp{
  @ApiProperty()
  @Length(5,5)
  @IsString()
  code: string
}