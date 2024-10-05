import { Request } from 'express';
import { Roles } from '../enums/role.enum';

export interface CustomRequest extends Request {
  user?: {
    id: number;
    role: Roles;
    [key: string]: any;
  };
  cookies: { [key: string]: string };
}
