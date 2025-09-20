import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello World!';
  }

  getUsers() {
    return [
      { id: 1, name: 'John Doe' },
      { id: 2, name: 'Jane Doe' },
    ];
  }
}
