import { BaseEntity } from '../../../common/abstarcts/base.entity';
import { EntityName } from 'src/common/enums/entity.enum';
import { UserEntity } from 'src/modules/user/entities/user.entity';
import { Column, Entity, ManyToOne } from 'typeorm';
import { EventEntity } from './event.entity';

@Entity(EntityName.SaveReserve)
export class SaveReserveEntity extends BaseEntity {
  @Column()
  rsId: number;
  @Column()
  userId: number;
  @ManyToOne(() => UserEntity, (user) => user.rs, {
    onDelete: 'CASCADE',
  })
  user: UserEntity;
  @ManyToOne(() => EventEntity, (event) => event.rs, { onDelete: 'CASCADE' })
  event: EventEntity;
}
