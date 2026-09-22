// Vercel Serverless Function entry point.
// Reuses the existing Express application so all /api routes
// (health check, scan pipeline) run unchanged on Vercel.
import app from '../server/index.js';

export default app;
