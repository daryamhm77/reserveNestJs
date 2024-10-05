import { BaseEntity } from 'src/common/abstarcts/base.entity';
import { EntityName } from 'src/common/enums/entity.enum';
import { UserEntity } from 'src/modules/user/entities/user.entity';
import {
  Entity,
  Column,
  ManyToOne,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ReserveEntity } from './reserve.entity';
import { SaveReserveEntity } from './saveReserv.entity';

@Entity(EntityName.Event)
export class EventEntity extends BaseEntity {
  @Column()
  title: string;
  @Column()
  time: Date;
  @Column()
  content: string;
  @CreateDateColumn()
  created_at: Date;
  @UpdateDateColumn()
  updated_at: Date;
  @OneToMany(() => ReserveEntity, (reserve) => reserve.event)
  reserve: ReserveEntity;
  @OneToMany(() => SaveReserveEntity, (rs) => rs.event)
  rs: SaveReserveEntity;
}
