import 'reflect-metadata';
import { createConnection } from 'typeorm';
import express from 'express';
import morgan from 'morgan';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';

dotenv.config();

import trim from './middlewares/trim';
import authRoutes from './routes/auth';

const PORT = process.env.PORT || 5000;

const app = express();
app.use(express.json());
app.use(morgan('dev'));
app.use(trim);
app.use(cookieParser());

app.get('/', (_, res) => res.send('HELLO'));

app.use('/api/v1/auth', authRoutes);

app.listen(5000, async () => {
  console.log(`Server running ${process.env.NODE_ENV} on port ${PORT}`);
  try {
    await createConnection();
    console.log('Database Connected');
  } catch (error) {
    console.error(error);
  }
});
