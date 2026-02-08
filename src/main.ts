import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DataSource } from 'typeorm';
import { seedPermissions } from './seed/permissions.seed';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Set global prefix
  app.setGlobalPrefix('api');

  // Enable CORS for frontend (add your production URLs)
  app.enableCors({
    origin: [
      'http://localhost:5173',
      'http://localhost:5174',
      'http://localhost:3001',
      'https://inestamode.netlify.app',
      'https://your-frontend-domain.vercel.app', // Replace with your actual frontend URL
      'https://your-frontend-domain.netlify.app', // Replace with your actual frontend URL
    ],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });

  // Seed permissions and initial admin on startup
  // This is safe to run in production as it checks for existence first
  const dataSource = app.get(DataSource);
  await seedPermissions(dataSource);

  // Use environment port or default to 3000
  const port = process.env.PORT || 3000;
  await app.listen(port, '0.0.0.0');

  console.log(`🚀 Application is running on port ${port}`);
}
bootstrap();
