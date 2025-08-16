// STEP 1: IMPORT REQUIRED MODULES

require('dotenv').config();

const express = require('express');    // Web framework for Node.js
const cors = require('cors');          // Enables cross-origin requests
const helmet = require('helmet');      // Security middleware (sets HTTP headers)
const morgan = require('morgan');      // HTTP request logger

// Database imports
const { sequelize } = require('./src/models'); // Sequelize ORM for PostgreSQL
// const redisClient = require('./src/config/redis'); // Redis for caching (we'll add this later)

// Utility imports
const logger = require('./src/utils/logger'); // Winston logger for application logs

// Middleware imports (we'll create these in later steps)
// const errorHandler = require('./src/middlewares/errorHandler');
// const rateLimiter = require('./src/middlewares/rateLimiter');

// Route imports (we'll create these in later steps)
// const routes = require('./src/routes');

// STEP 2: CREATE EXPRESS APPLICATION INSTANCE
const app = express();      //Create Express application instance

// STEP 3: CONFIGURATION VARIABLES
// Get configuration from environment variables with fallback defaults
const PORT = process.env.PORT || 3000;           // Server port
const NODE_ENV = process.env.NODE_ENV || 'development'; // Environment (dev/prod)
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';     // CORS allowed origins

// Log startup information
logger.info(`🚀 Starting Multi-Tenant SaaS API in ${NODE_ENV} mode`);
logger.info(`📊 Server will run on port ${PORT}`);

// STEP 4: SECURITY MIDDLEWARE
/**
 * HELMET - Security middleware that sets various HTTP headers
 * - X-Content-Type-Options: nosniff (prevents MIME type sniffing)
 * - X-Frame-Options: DENY (prevents clickjacking)
 * - X-XSS-Protection: 1; mode=block (enables XSS filtering)
 * - And many more security headers
 */
app.use(helmet());

/**
 * CORS - Cross-Origin Resource Sharing
 * Allows frontend applications running on different domains to access our API
 * In production, replace '*' with specific frontend URLs for better security
 */
app.use(cors({
    origin: CORS_ORIGIN === '*' ? '*' : CORS_ORIGIN.split(','),    // Convert comma-separated string to array
    credentials: true,         // Allow cookies and auth headers
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],    // Allowed HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization']      // Allowed request headers
}));

// STEP 5: REQUEST PARSING MIDDLEWARE
/**
 * JSON Parser - Parses incoming JSON payloads
 * limit: '10mb' prevents huge payloads that could crash the server
 * Without this, req.body would be undefined for JSON requests
 */
app.use(express.json({ limit: '10mb' }));

/**
 * URL Encoded Parser - Parses form data (application/x-www-form-urlencoded)
 * extended: true allows for rich objects and arrays in form data
 * This handles HTML form submissions
 */
app.use(express.urlencoded({ extended: true }));

// STEP 6: LOGGING MIDDLEWARE
/**
 * MORGAN - HTTP request logger
 * In development: shows detailed colored logs for each request
 * In production: uses 'combined' format for structured logs
 */
if (NODE_ENV === 'development') {
    // Development logging: colorful and detailed
    app.use(morgan('dev')); // Shows: GET /api/users 200 15ms - 1.2kb
} else {
    // Production logging: structured format for log analysis tools
    app.use(morgan('combined')); // Shows: IP, timestamp, method, URL, status, size, user-agent
}

// STEP 7: HEALTH CHECK ENDPOINT
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK',                           // Simple status indicator
        timestamp: new Date().toISOString(),    // Current server time
        uptime: process.uptime(),               // How long server has been running (seconds)
        environment: NODE_ENV,                  // Current environment
        version: process.env.npm_package_version || '1.0.0', // App version from package.json
        node_version: process.version,          // Node.js version
        memory_usage: process.memoryUsage()     // Memory consumption stats
    });
});

// STEP 8: API ROUTES
/**
 * Main API Routes
 * All our business logic routes will be mounted under /api
 * This makes it clear which endpoints are API vs static files/health checks
 */
// app.use('/api', rateLimiter); // Apply rate limiting to all API routes
// app.use('/api', routes);       // Mount all our API routes

// Temporary welcome route for testing
app.get('/', (req, res) => {
    res.json({
        message: '🎉 Multi-Tenant SaaS API is running!',
        documentation: '/api/docs',
        health: '/health',
        timestamp: new Date().toISOString()
    });
});

// STEP 9: ERROR HANDLING MIDDLEWARE
/**
 * 404 Handler - Catches all unmatched routes
 * This runs when no other route matches the request
 */
app.use('*', (req, res) => {
    logger.warn(`404 - Route not found: ${req.method} ${req.originalUrl}`);
    res.status(404).json({
        error: 'Route not found',
        message: `Cannot ${req.method} ${req.originalUrl}`,
        timestamp: new Date().toISOString()
    });
});

/**
 * Global Error Handler
 * This catches all errors thrown by routes or middleware
 * Must have 4 parameters (err, req, res, next) to be recognized as error handler
 */
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', {
        error: err.message,
        stack: err.stack,
        method: req.method,
        url: req.originalUrl,
        ip: req.ip
    });

    // Don't expose error details in production
    const message = NODE_ENV === 'development' ? err.message : 'Internal server error';
    const stack = NODE_ENV === 'development' ? err.stack : undefined;

    res.status(err.status || 500).json({
        error: message,
        ...(stack && { stack }), // Only include stack trace in development
        timestamp: new Date().toISOString()
    });
});

// STEP 10: DATABASE CONNECTION & SERVER STARTUP
async function startServer() {
    try {
        logger.info('🔄 Starting server initialization...');
        // DATABASE CONNECTION TEST
        logger.info('📊 Testing PostgreSQL connection...');
        
        // Test database connection
        await sequelize.authenticate();
        logger.info('✅ PostgreSQL connection successful');

        // In development, sync models (create/update tables)
        // In production, we use migrations instead for better control
        if (NODE_ENV === 'development') {
            logger.info('🔄 Syncing database models...');
            await sequelize.sync({ alter: true }); // alter: true updates existing tables
            logger.info('✅ Database models synced');
        }

        // REDIS CONNECTION
        /*
        logger.info('🔴 Testing Redis connection...');
        await redisClient.ping();
        logger.info('✅ Redis connection successful');
        */

        // START HTTP SERVER
        const server = app.listen(PORT, () => {
            logger.info(`🚀 Server is running on port ${PORT}`);
            logger.info(`📍 Health check: http://localhost:${PORT}/health`);
            logger.info(`🌐 API base URL: http://localhost:${PORT}/api`);
            logger.info(`📚 Environment: ${NODE_ENV}`);
        });

        // GRACEFUL SHUTDOWN HANDLING
        /**
         * Graceful Shutdown
         * When the server receives termination signals (SIGTERM, SIGINT),
         * it closes connections gracefully instead of abruptly stopping
         */
        const gracefulShutdown = (signal) => {
            logger.info(`📴 Received ${signal}. Starting graceful shutdown...`);
            
            server.close(async () => {
                logger.info('🔌 HTTP server closed');
                
                try {
                    // Close database connections
                    await sequelize.close();
                    logger.info('📊 Database connections closed');
                    
                    // Close Redis connection
                    // await redisClient.quit();
                    // logger.info('🔴 Redis connection closed');
                    
                    logger.info('✅ Graceful shutdown complete');
                    process.exit(0);
                } catch (error) {
                    logger.error('❌ Error during shutdown:', error);
                    process.exit(1);
                }
            });
        };

        // Listen for termination signals
        process.on('SIGTERM', () => gracefulShutdown('SIGTERM')); // Docker/Kubernetes shutdown
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));   // Ctrl+C

    } catch (error) {
        logger.error('❌ Failed to start server:', error);
        process.exit(1); // Exit with error code
    }
}

// STEP 11: START THE SERVER
if (require.main === module) {
    startServer();
}

