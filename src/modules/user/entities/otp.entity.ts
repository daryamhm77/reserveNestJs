/* eslint-disable prettier/prettier */

import { Column, Entity, OneToOne } from "typeorm";
import { BaseEntity } from 'src/common/abstarcts/base.entity';
import { UserEntity } from "./user.entity";
import { EntityName } from 'src/common/enums/entity.enum';

@Entity(EntityName.Otp)
export class OtpEntity extends BaseEntity {
  @Column()
  code: string;
  @Column({nullable: true })
  expiresIn: Date;
  @Column()
  userId: number;
  @Column()
  method: string;
  @OneToOne(()=> UserEntity,user=> user.otp, {onDelete:"CASCADE"})
  user: UserEntity
}
