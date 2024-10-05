import { BaseEntity } from 'src/common/abstarcts/base.entity';
import { EntityName } from 'src/common/enums/entity.enum';
import { Column, Entity } from 'typeorm';

@Entity(EntityName.Category)
export class CategoryEntity implements BaseEntity {
  id: number;
  @Column()
  title: string;
  @Column({ nullable: true })
  priority: number;
}
