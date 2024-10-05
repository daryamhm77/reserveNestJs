import { Inject, Injectable, NotFoundException, Scope } from '@nestjs/common';
import { UpdateEventDto, EventDto } from './dto/event.dto';
import { REQUEST } from '@nestjs/core';
import { InjectRepository } from '@nestjs/typeorm';
import { EventEntity } from './entities/event.entity';
import { Repository } from 'typeorm';
import { ReserveEntity } from './entities/reserve.entity';
import { NotFoundMessage, PublicMessage } from 'src/common/enums/message.enum';
import { SaveReserveEntity } from './entities/saveReserv.entity';
import { Request } from 'express';
import { CustomRequest } from 'src/common/interface/user.interface';

@Injectable({ scope: Scope.REQUEST })
export class EventsService {
  constructor(
    @InjectRepository(EventEntity)
    private eventRepository: Repository<EventEntity>,
    @InjectRepository(ReserveEntity)
    private reserveRepository: Repository<ReserveEntity>,
    @InjectRepository(SaveReserveEntity)
    private savereserveRepository: Repository<SaveReserveEntity>,
    @Inject(REQUEST) private request: CustomRequest,
  ) {}

  async create(eventDto: EventDto) {
    const user = this.request.user;
    const { title, time, content } = eventDto;
    let event = this.eventRepository.create({
      title,
      time,
      content,
    });
    event = await this.eventRepository.save(event);
    return event;
  }

  findAll() {
    return this.eventRepository.find({});
  }

  async findOne(id: number) {
    const event = await this.eventRepository.findOneBy({ id });
    if (!event) throw new NotFoundException(NotFoundMessage.NotFoundevent);
    return event;
  }

  async update(id: number, eventDto: UpdateEventDto) {
    const event = await this.eventRepository.findOne({ where: { id } });
    const { title, time, content } = eventDto;
    if (title) event.title = title;
    if (time) event.time = time;
    if (content) event.content = content;

    await this.eventRepository.save(event);
    return {
      message: PublicMessage.Updated,
    };
  }

  async remove(id: number) {
    await this.checkExistReserveById(id);
    await this.eventRepository.delete({ id });
    return {
      message: PublicMessage.Deleted,
    };
  }

  async checkExistReserveById(id: number) {
    const blog = await this.eventRepository.findOneBy({ id });
    if (!blog) throw new NotFoundException(NotFoundMessage.NotFoundPost);
    return blog;
  }

  async reserveToggle(rsId: number) {
    const { id: userId } = this.request.user;;
    const blog = await this.checkExistReserveById(rsId);
    const isLiked = await this.savereserveRepository.findOneBy({
      userId,
      rsId,
    });
    let message = PublicMessage.Like;
    if (isLiked) {
      await this.savereserveRepository.delete({ id: isLiked.id });
      message = PublicMessage.DisLike;
    } else {
      await this.savereserveRepository.insert({
        rsId,
        userId,
      });
    }
    return { message };
  }
}
