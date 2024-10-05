/* eslint-disable prettier/prettier */
namespace NodeJs {
  interface ProcessEnv {
    ///App
    PORT: number;
    ///database
    DB_PORT: number;
    DB_NAME: string;
    DB_USERNAME: string;
    DB_PASSWORD: string;
    DB_HOST: string;
    ///secret-key-cookie
    SECRET_KEY: string;
    OTP_TOKEN: string;
    ACCESS_TOKEN: string;
    PHONE_TOKEN_SECRET: string;
  }
}
