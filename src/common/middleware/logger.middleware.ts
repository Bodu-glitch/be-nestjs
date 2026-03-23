import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  private readonly logger = new Logger('HTTP');

  use(req: Request, res: Response, next: NextFunction) {
    const { method, originalUrl, body } = req;
    const start = Date.now();

    res.on('finish', () => {
      const ms = Date.now() - start;
      this.logger.log(`${method} ${originalUrl} ${res.statusCode} +${ms}ms`);
    });

    const isMultipart = req.headers['content-type']?.includes('multipart/form-data');
    if (body && Object.keys(body).length > 0 && !isMultipart) {
      this.logger.debug(`Body: ${JSON.stringify(body)}`);
    }

    next();
  }
}
