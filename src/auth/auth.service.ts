import { Injectable } from '@nestjs/common';
import { AuthBody } from './auth.controller';
import { PrismaService } from '../prisma.service';
import { hash, compare } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserPayload } from './jwt.strategy';
import { CreateUser } from './auth.controller';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private jwtService: JwtService,
  ) {}
  // login
  async login({ authBody }: { authBody: AuthBody }) {
    if (!authBody) {
      throw new Error('Invalid request body');
    }

    const { email, password } = authBody;

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
    return this.athenticateUser({ userId: existingUser.id });
  }
  // register
  async register({ registerBody }: { registerBody: CreateUser }) {
    const { name, email, password } = registerBody;

    const existingUser = await this.prisma.user.findUnique({
      where: {
        email: registerBody.email,
      },
    });
    const hashedPassword = await this.hashPassword({ password });
    if (existingUser) {
      throw new Error('User already exists');
    }
    const createdUser = await this.prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });
    return this.athenticateUser({ userId: createdUser.id });
  }
  async authenticateUser({ authBody }: { authBody: AuthBody }) {
    if (!authBody) {
      throw new Error('Invalid request body');
    }

    const { email, password } = authBody;

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
    return this.athenticateUser({ userId: existingUser.id });
  }

  // hash password
  private async hashPassword({ password }: { password: string }) {
    const hashedPassword = await hash(password, 10);
    return hashedPassword;
  }
  // compare password
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
  // authenticate user
  private async athenticateUser({ userId }: UserPayload) {
    const payload: UserPayload = { userId };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
