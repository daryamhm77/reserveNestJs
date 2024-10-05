import { BaseEntity } from 'src/common/abstarcts/base.entity';
import { EntityName } from 'src/common/enums/entity.enum';
import { OtpEntity } from './otp.entity';
import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  OneToMany,
  OneToOne,
  UpdateDateColumn,
} from 'typeorm';
import { ReserveEntity } from 'src/modules/events/entities/reserve.entity';
import { SaveReserveEntity } from 'src/modules/events/entities/saveReserv.entity';
import { Roles } from 'src/common/enums/role.enum';

@Entity(EntityName.User)
export class UserEntity extends BaseEntity {
  @Column({ unique: true })
  username: string;
  @Column({ unique: true, nullable: true })
  phone: string;
  @Column({ unique: true, nullable: true })
  email: string;
  @Column({ nullable: true, default: false })
  verify_phone: boolean;
  @Column({ nullable: true, default: false })
  verify_email: boolean;
  @Column({ nullable: true })
  password: string;
  @Column({default: Roles.Admin})
  role: Roles;
  @CreateDateColumn()
  create_at: Date;
  @UpdateDateColumn()
  update_at: Date;
  @Column({ nullable: true })
  otpId: number;
  @OneToOne(() => OtpEntity, (otp) => otp.user, { nullable: true })
  @JoinColumn()
  otp: OtpEntity;
  @OneToMany(()=> ReserveEntity, (reserve)=> reserve.user)
  reserve: ReserveEntity;
  @OneToMany(()=> SaveReserveEntity, (rs)=> rs.user)
  rs: SaveReserveEntity
}
