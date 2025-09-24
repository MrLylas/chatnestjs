import {
  Body,
  Controller,
  Post,
  Get,
  UseGuards,
  Request,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { UserService } from 'src/user/user.service';
import type { RequestWithUser } from './jwt.strategy';

export type AuthBody = {
  email: string;
  password: string;
};
export type CreateUser = {
  name: string;
  email: string;
  password: string;
};
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly UserService: UserService,
  ) {}
  @Post('login')
  async login(@Body() authBody: AuthBody) {
    return await this.authService.login({ authBody });
  }
  @Post('register')
  async register(@Body() registerBody: CreateUser) {
    return await this.authService.register({
      registerBody,
    });
  }
  @Get()
  @UseGuards(JwtAuthGuard)
  async authenticateUser(@Request() request: RequestWithUser) {
    return await this.UserService.getUser({ userId: request.user.userId });
  }
}
