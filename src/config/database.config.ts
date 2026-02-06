import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';

export const getDatabaseConfig = (
  configService: ConfigService,
): TypeOrmModuleOptions => {
  const databaseUrl = configService.get<string>('DATABASE_URL');
  const isProduction = configService.get<string>('NODE_ENV') === 'production';

  // Base configuration
  const baseConfig: TypeOrmModuleOptions = {
    type: 'postgres',
    entities: [__dirname + '/../**/*.entity{.ts,.js}'],
    synchronize: true, // Keep true for initial dev/deployment, change to false later
    logging: !isProduction,
    autoLoadEntities: true,
  };

  // If DATABASE_URL is provided (typical for Railway/Supabase)
  if (databaseUrl) {
    return {
      ...baseConfig,
      url: databaseUrl,
      ssl: {
        rejectUnauthorized: false,
      },
    };
  }

  // Fallback to individual parameters (local dev or manual config)
  const password = configService.get<string>('DB_PASSWORD');
  const host = configService.get<string>('DB_HOST', 'localhost');
  const isSupabase = host.includes('supabase.com') || host.includes('supabase.co');

  return {
    ...baseConfig,
    host,
    port: configService.get<number>('DB_PORT', 5432),
    username: configService.get<string>('DB_USERNAME', 'postgres'),
    password: password || '',
    database: configService.get<string>('DB_DATABASE', 'inesta_mode'),
    ssl: isSupabase || isProduction ? { rejectUnauthorized: false } : false,
  };
};
