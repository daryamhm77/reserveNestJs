/* eslint-disable prettier/prettier */
import { UserEntity } from "src/modules/users/entities/user.entity";
declare global {
  namespace express {
    interface REQUEST {
      user?: UserEntity;
    }
  }
}
