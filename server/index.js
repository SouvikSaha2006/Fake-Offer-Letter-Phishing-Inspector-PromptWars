import express from 'express';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import fs from 'fs';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import scanRouter from './routes/scan.js';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

// Trust proxy for rate-limiting when behind reverse proxy (e.g. Google Cloud Run)
app.set('trust proxy', 1);

// HTTP Security Hardening (Helmet)
app.use(
  helmet({
    contentSecurityPolicy: false, // Permits Vite frontend assets and Google Fonts
    crossOriginEmbedderPolicy: false
  })
);

// Enable CORS and body parsing with bounded limits
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// Rate Limiter: Max 60 requests per minute per IP to protect against abuse
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Rate limit exceeded. Maximum 60 requests per minute allowed per IP.'
  }
});

// Apply rate limiter to all API endpoints
app.use('/api', apiLimiter);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// Forensic scan routes
app.use('/api', scanRouter);

// Static assets serving for frontend client
const clientDistPath = path.resolve(__dirname, '../client/dist');
app.use(express.static(clientDistPath));

// Fallback route for single-page application (SPA) routing
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'API route not found' });
  }

  const indexPath = path.join(clientDistPath, 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(200).send('PhishGuard Inspector API Server is running. Client build not found at client/dist.');
  }
});

// Start listener only when executed directly (not when imported in test suites)
const isDirectRun = Boolean(process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href);
if (isDirectRun && process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`[PhishGuard Server] Running on http://localhost:${PORT}`);
  });
}

export default app;
