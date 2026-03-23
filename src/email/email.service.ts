import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';

@Injectable()
export class EmailService {
  private resend: Resend;
  private from: string;
  private frontendUrl: string;

  constructor(private config: ConfigService) {
    this.resend = new Resend(this.config.get<string>('RESEND_API_KEY'));
    this.from = this.config.get<string>('RESEND_FROM_EMAIL', 'onboarding@resend.dev');
    this.frontendUrl = this.config.get<string>('APP_FRONTEND_URL', 'http://localhost:3001');
  }

  async sendOtpEmail(email: string, otp: string): Promise<void> {
    try {
      await this.resend.emails.send({
        from: this.from,
        to: email,
        subject: 'Mã OTP đặt lại mật khẩu',
        html: `<p>Mã OTP của bạn là: <strong>${otp}</strong></p><p>Mã có hiệu lực trong 10 phút.</p>`,
      });
    } catch (err) {
      console.error('[EmailService] Failed to send OTP email:', err);
    }
  }

  async sendInvitationEmail(email: string, token: string): Promise<void> {
    const link = `${this.frontendUrl}/register?token=${token}`;
    try {
      await this.resend.emails.send({
        from: this.from,
        to: email,
        subject: 'Lời mời tham gia hệ thống',
        html: `<p>Bạn đã được mời tham gia hệ thống. Nhấp vào liên kết bên dưới để đăng ký:</p><p><a href="${link}">${link}</a></p><p>Liên kết có hiệu lực trong 24 giờ.</p>`,
      });
    } catch (err) {
      console.error('[EmailService] Failed to send invitation email:', err);
    }
  }

  async sendInvitationAcceptEmail(email: string, token: string): Promise<void> {
    const link = `${this.frontendUrl}/accept-invitation?token=${token}`;
    try {
      await this.resend.emails.send({
        from: this.from,
        to: email,
        subject: 'Lời mời tham gia tenant mới',
        html: `<p>Bạn được mời tham gia một tenant mới. Click để xác nhận:</p><p><a href="${link}">${link}</a></p><p>Hoặc accept trực tiếp trong ứng dụng. Link có hiệu lực 24 giờ.</p>`,
      });
    } catch (err) {
      console.error('[EmailService] Failed to send invitation accept email:', err);
    }
  }
}
