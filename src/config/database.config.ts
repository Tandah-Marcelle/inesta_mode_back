import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';

export const getDatabaseConfig = (
  configService: ConfigService,
): TypeOrmModuleOptions => {
  const password = configService.get<string>('DB_PASSWORD');
  const isSupabase = configService.get<string>('DB_HOST', '').includes('supabase.com');
  
  return {
    type: 'postgres',
    host: configService.get<string>('DB_HOST', 'localhost'),
    port: configService.get<number>('DB_PORT', 5432),
    username: configService.get<string>('DB_USERNAME', 'postgres'),
    password: password || '', // Use empty string instead of undefined for PostgreSQL
    database: configService.get<string>('DB_DATABASE', 'inesta_mode'),
    entities: [__dirname + '/../**/*.entity{.ts,.js}'],
    synchronize: configService.get<string>('NODE_ENV') === 'development',
    logging: configService.get<string>('NODE_ENV') === 'development',
    autoLoadEntities: true,
    ssl: isSupabase ? true : (configService.get<string>('NODE_ENV') === 'production' ? { rejectUnauthorized: false } : false),
    extra: isSupabase ? {
      ssl: {
        rejectUnauthorized: false,
      },
    } : {},
  };
};
