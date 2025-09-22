import { Injectable } from '@nestjs/common';
import { AuthBody } from './auth.controller';
import { PrismaService } from '../prisma.service';
import { hash, compare } from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}
  async login({ authBody }: { authBody: AuthBody }) {
    if (!authBody) {
      throw new Error('Invalid request body');
    }

    const { email, password } = authBody;

    const hashPassword = await this.hashPassword({ password });
    console.log(hashPassword, password);
    const existingUser = await this.prisma.user.findUnique({
      where: {
        email: authBody.email,
      },
    });
    if (!existingUser) {
      throw new Error('User not found');
    }
    const isPasswordValid = await this.IsPasswordValid({
      password,
      hashedPassword: existingUser.password,
    });
    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }
    return existingUser.id;
  }

  private async hashPassword({ password }: { password: string }) {
    const hashedPassword = await hash(password, 10);
    return hashedPassword;
  }
  private async IsPasswordValid({
    password,
    hashedPassword,
  }: {
    password: string;
    hashedPassword: string;
  }) {
    const isPasswordValid = await compare(password, hashedPassword);
    return isPasswordValid;
  }
}
