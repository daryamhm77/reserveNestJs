import { EntityName } from 'src/common/enums/entity.enum';
import { UserEntity } from 'src/modules/user/entities/user.entity';
import { Column, Entity, ManyToOne } from 'typeorm';
import { BaseEntity } from 'src/common/abstarcts/base.entity';
import { EventEntity } from './event.entity';

@Entity(EntityName.Reserve)
export class ReserveEntity extends BaseEntity {
  @Column()
  reserveId: number;
  @Column()
  userId: number;
  @ManyToOne(() => UserEntity, (user) => user.reserve, {
    onDelete: 'CASCADE',
  })
  user: UserEntity;
  @ManyToOne(() => EventEntity, (event) => event.reserve, {
    onDelete: 'CASCADE',
  })
  event: EventEntity;
}
