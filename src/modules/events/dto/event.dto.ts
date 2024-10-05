import { ApiProperty, PartialType } from '@nestjs/swagger';
import { IsNotEmpty, Length } from 'class-validator';

export class EventDto {
  @ApiProperty()
  @IsNotEmpty()
  @Length(10, 150)
  title: string;
  @ApiProperty()
  @IsNotEmpty()
  @Length(100)
  content: string;
  @ApiProperty()
  @IsNotEmpty()
  time: Date;
}
export class UpdateEventDto extends PartialType(EventDto) {}
