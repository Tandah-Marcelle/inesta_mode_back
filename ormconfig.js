const { DataSource } = require('typeorm');
require('dotenv').config();

const isSupabase = (process.env.DB_HOST || '').includes('supabase.com');

const dataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  username: process.env.DB_USERNAME || 'postgres',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE || 'inesta_mode',
  entities: ['dist/src/**/*.entity.js'],
  migrations: ['dist/src/migrations/*.js'],
  synchronize: false,
  logging: false,
  ssl: isSupabase ? true : false,
  extra: isSupabase ? {
    ssl: {
      rejectUnauthorized: false,
    },
  } : {},
});

module.exports = dataSource;