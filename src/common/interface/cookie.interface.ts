import { Request } from 'express';

export interface CustomRequestCookies extends Request {
  cookies: { [key: string]: string };
}
