require('dotenv').config();
const { DataSource } = require('typeorm');
const { seedPermissions } = require('./dist/src/seed/permissions.seed');

async function runSeed() {
  console.log('Environment variables loaded:');
  console.log('DB_HOST:', process.env.DB_HOST);
  console.log('DB_PORT:', process.env.DB_PORT);
  console.log('DB_USERNAME:', process.env.DB_USERNAME);
  console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? '***HIDDEN***' : 'NOT SET');
  console.log('DB_DATABASE:', process.env.DB_DATABASE);

  const dataSource = new DataSource({
    type: 'postgres',
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT),
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    ssl: true,
    extra: {
      ssl: {
        rejectUnauthorized: false,
      },
    },
    entities: ['dist/src/entities/*.entity.js'],
    synchronize: false,
  });

  try {
    await dataSource.initialize();
    console.log('Database connected successfully');
    
    await seedPermissions(dataSource);
    console.log('Permissions seeded successfully');
    
    await dataSource.destroy();
    console.log('Database connection closed');
  } catch (error) {
    console.error('Error seeding permissions:', error);
    process.exit(1);
  }
}

runSeed();