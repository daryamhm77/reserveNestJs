import { Module } from '@nestjs/common';
import { EventsService } from './events.service';
import { EventsController } from './events.controller';
import { AuthModule } from '../auth/auth.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { EventEntity } from './entities/event.entity';
import { ReserveEntity } from './entities/reserve.entity';
import { SaveReserveEntity } from './entities/saveReserv.entity';

@Module({
  imports: [
    AuthModule,
    TypeOrmModule.forFeature([EventEntity, ReserveEntity, SaveReserveEntity]),
  ],
  controllers: [EventsController],
  providers: [EventsService],
})
export class EventsModule {}
