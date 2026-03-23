import { Injectable, OnModuleDestroy, OnModuleInit, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, RedisClientType } from 'redis';

const OTP_TTL_SECONDS = 600; // 10 minutes

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private client: RedisClientType;

  constructor(private config: ConfigService) {}

  async onModuleInit() {
    this.client = createClient({
      username: this.config.getOrThrow<string>('REDIS_USERNAME'),
      password: this.config.getOrThrow<string>('REDIS_PASSWORD'),
      socket: {
        host: this.config.getOrThrow<string>('REDIS_HOST'),
        port: this.config.getOrThrow<number>('REDIS_PORT'),
      },
    }) as RedisClientType;

    this.client.on('error', (err) => {
      console.error('[Redis] Connection error:', err.message);
    });

    await this.client.connect();
  }

  async onModuleDestroy() {
    await this.client.quit();
  }

  async setOtp(email: string, otp: string): Promise<void> {
    try {
      await this.client.set(`otp:${email}`, otp, { EX: OTP_TTL_SECONDS });
    } catch (err) {
      throw new ServiceUnavailableException({ code: 'REDIS_UNAVAILABLE', message: 'Could not store OTP. Please try again later.' });
    }
  }

  async getOtp(email: string): Promise<string | null> {
    try {
      return await this.client.get(`otp:${email}`);
    } catch (err) {
      throw new ServiceUnavailableException({ code: 'REDIS_UNAVAILABLE', message: 'Could not verify OTP. Please try again later.' });
    }
  }

  async deleteOtp(email: string): Promise<void> {
    try {
      await this.client.del(`otp:${email}`);
    } catch {
      console.error(`[Redis] Failed to delete OTP key for ${email}`);
    }
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    try {
      await this.client.set(key, value, { EX: ttlSeconds });
    } catch (err) {
      throw new ServiceUnavailableException({ code: 'REDIS_UNAVAILABLE', message: 'Redis unavailable. Please try again later.' });
    }
  }

  async get(key: string): Promise<string | null> {
    try {
      return await this.client.get(key);
    } catch (err) {
      throw new ServiceUnavailableException({ code: 'REDIS_UNAVAILABLE', message: 'Redis unavailable. Please try again later.' });
    }
  }

  async delete(key: string): Promise<void> {
    try {
      await this.client.del(key);
    } catch {
      console.error(`[Redis] Failed to delete key ${key}`);
    }
  }
}
