// ============================================================================
// FILE: src/server.ts
// Main Express server setup
// ============================================================================

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'http';
import { config } from './config';
import { setupWebSocket } from './websocket/server';
import { errorHandler } from './middleware/errorHandler';
import { apiLimiter } from './middleware/rateLimiter';
import authRoutes from './routes/auth.routes';
import executeRoutes from './routes/execute.routes';
import projectRoutes from './routes/project.routes';
import fileRoutes from './routes/file.routes';
import systemRoutes from './routes/system.routes';

const app = express();
const httpServer = createServer(app);

// Global middleware
app.use(helmet());
app.use(cors({
  origin: config.cors.origin,
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
app.use('/api/', apiLimiter);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// API Routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/execute', executeRoutes);
app.use('/api/v1/projects', projectRoutes);
app.use('/api/v1/files', fileRoutes);
app.use('/api/v1', systemRoutes);

// WebSocket setup
export const io = setupWebSocket(httpServer);

// Error handler (must be last)
app.use(errorHandler);

// Start server
const PORT = config.port;
httpServer.listen(PORT, () => {
  console.log(`🚀 MUSCode API Server running on port ${PORT}`);
  console.log(`📡 WebSocket server ready at ws://localhost:${PORT}/ws`);
});

export default app;

// ============================================================================
// FILE: src/config/index.ts
// Configuration management
// ============================================================================

import dotenv from 'dotenv';
dotenv.config();

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  
  database: {
    url: process.env.DATABASE_URL || 'postgresql://localhost:5432/muscode'
  },
  
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379'
  },
  
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
    expiresIn: process.env.JWT_EXPIRATION || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRATION || '7d'
  },
  
  cors: {
    origin: process.env.CORS_ORIGIN || '*'
  },
  
  execution: {
    timeout: parseInt(process.env.EXECUTION_TIMEOUT || '30', 10),
    memoryLimit: parseInt(process.env.MEMORY_LIMIT || '256', 10),
    maxCodeLength: parseInt(process.env.MAX_CODE_LENGTH || '50000', 10)
  },
  
  docker: {
    socketPath: process.env.DOCKER_SOCKET || '/var/run/docker.sock'
  }
};

// ============================================================================
// FILE: src/middleware/auth.ts
// JWT Authentication middleware
// ============================================================================

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';

export interface AuthRequest extends Request {
  user?: {
    userId: string;
    email: string;
    username: string;
    role: string;
  };
}

export const authenticateJWT = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'No token provided'
      });
    }

    const token = authHeader.substring(7);
    
    try {
      const decoded = jwt.verify(token, config.jwt.secret) as any;
      req.user = {
        userId: decoded.userId,
        email: decoded.email,
        username: decoded.username,
        role: decoded.role
      };
      next();
    } catch (error) {
      return res.status(403).json({
        success: false,
        error: 'Invalid or expired token'
      });
    }
  } catch (error) {
    next(error);
  }
};

export const requireRole = (roles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: 'Insufficient permissions'
      });
    }
    
    next();
  };
};

// ============================================================================
// FILE: src/middleware/rateLimiter.ts
// Rate limiting configuration
// ============================================================================

import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { createClient } from 'redis';
import { config } from '../config';

const redisClient = createClient({ url: config.redis.url });
redisClient.connect();

export const apiLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient as any,
    prefix: 'rl:api:'
  }),
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

export const executionLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient as any,
    prefix: 'rl:exec:'
  }),
  windowMs: 60 * 1000,
  max: 10,
  message: { success: false, error: 'Too many code executions, please wait' }
});

export const authLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient as any,
    prefix: 'rl:auth:'
  }),
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, error: 'Too many authentication attempts' }
});

// ============================================================================
// FILE: src/middleware/errorHandler.ts
// Global error handler
// ============================================================================

import { Request, Response, NextFunction } from 'express';

export class AppError extends Error {
  statusCode: number;
  isOperational: boolean;

  constructor(message: string, statusCode: number) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

export const errorHandler = (
  err: Error | AppError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (err instanceof AppError) {
    return res.status(err.statusCode).json({
      success: false,
      error: err.message
    });
  }

  console.error('Unexpected error:', err);
  
  return res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
};

// ============================================================================
// FILE: src/services/dockerExecutor.ts
// Docker code execution engine
// ============================================================================

import Docker from 'dockerode';
import { promises as fs } from 'fs';
import path from 'path';
import { config } from '../config';

export interface ExecutionConfig {
  language: string;
  code: string;
  stdin?: string;
  timeout?: number;
  memoryLimit?: number;
}

export interface ExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  executionTime: number;
  memoryUsed: number;
  timedOut: boolean;
  compilationError?: string;
}

export class DockerExecutor {
  private docker: Docker;
  private imageMap: Map<string, string>;
  private commandMap: Map<string, string[]>;
  private extensionMap: Map<string, string>;

  constructor() {
    this.docker = new Docker({ socketPath: config.docker.socketPath });
    
    this.imageMap = new Map([
      ['python', 'python:3.11-slim'],
      ['javascript', 'node:20-slim'],
      ['java', 'openjdk:17-slim'],
      ['cpp', 'gcc:11'],
      ['c', 'gcc:11'],
      ['php', 'php:8.2-cli-alpine']
    ]);

    this.commandMap = new Map([
      ['python', ['python', '/workspace/main.py']],
      ['javascript', ['node', '/workspace/main.js']],
      ['java', ['sh', '-c', 'cd /workspace && javac Main.java && java Main']],
      ['cpp', ['sh', '-c', 'cd /workspace && g++ -o main main.cpp && ./main']],
      ['c', ['sh', '-c', 'cd /workspace && gcc -o main main.c && ./main']],
      ['php', ['php', '/workspace/main.php']]
    ]);

    this.extensionMap = new Map([
      ['python', '.py'],
      ['javascript', '.js'],
      ['java', '.java'],
      ['cpp', '.cpp'],
      ['c', '.c'],
      ['php', '.php']
    ]);
  }

  async execute(execConfig: ExecutionConfig): Promise<ExecutionResult> {
    const startTime = Date.now();
    const timeout = execConfig.timeout || config.execution.timeout;
    const memoryLimit = execConfig.memoryLimit || config.execution.memoryLimit;

    const image = this.imageMap.get(execConfig.language);
    if (!image) {
      throw new Error(`Unsupported language: ${execConfig.language}`);
    }

    // Create workspace
    const workDir = path.join('/tmp', `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`);
    await this.prepareWorkspace(workDir, execConfig);

    let container: Docker.Container | null = null;
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let exitCode = 0;

    try {
      // Pull image if not exists
      await this.ensureImage(image);

      // Container configuration
      const containerConfig: Docker.ContainerCreateOptions = {
        Image: image,
        Cmd: this.commandMap.get(execConfig.language),
        HostConfig: {
          Memory: memoryLimit * 1024 * 1024,
          MemorySwap: memoryLimit * 1024 * 1024,
          NanoCpus: 1000000000,
          NetworkMode: 'none',
          ReadonlyRootfs: false,
          CapDrop: ['ALL'],
          SecurityOpt: ['no-new-privileges'],
          PidsLimit: 50,
          Binds: [`${workDir}:/workspace`],
          AutoRemove: false
        },
        WorkingDir: '/workspace',
        AttachStdout: true,
        AttachStderr: true,
        OpenStdin: !!execConfig.stdin,
        StdinOnce: true,
        Tty: false
      };

      // Create and start container
      container = await this.docker.createContainer(containerConfig);
      await container.start();

      // Setup timeout
      const timeoutHandle = setTimeout(async () => {
        timedOut = true;
        if (container) {
          try {
            await container.kill();
          } catch (e) {
            console.error('Error killing container:', e);
          }
        }
      }, timeout * 1000);

      // Attach streams
      const stream = await container.attach({
        stream: true,
        stdout: true,
        stderr: true,
        stdin: !!execConfig.stdin
      });

      // Write stdin if provided
      if (execConfig.stdin) {
        stream.write(execConfig.stdin);
        stream.end();
      }

      // Collect output
      await new Promise<void>((resolve, reject) => {
        const chunks: Buffer[] = [];
        
        stream.on('data', (chunk: Buffer) => {
          chunks.push(chunk);
        });

        stream.on('end', () => {
          // Docker multiplexes stdout/stderr
          // Format: [STREAM_TYPE, 0, 0, 0, SIZE1, SIZE2, SIZE3, SIZE4, DATA...]
          for (const chunk of chunks) {
            let offset = 0;
            while (offset < chunk.length) {
              if (chunk.length - offset < 8) break;
              
              const streamType = chunk[offset];
              const size = chunk.readUInt32BE(offset + 4);
              const data = chunk.slice(offset + 8, offset + 8 + size).toString();
              
              if (streamType === 1) {
                stdout += data;
              } else if (streamType === 2) {
                stderr += data;
              }
              
              offset += 8 + size;
            }
          }
          resolve();
        });

        stream.on('error', reject);
      });

      clearTimeout(timeoutHandle);

      // Wait for container to exit
      const result = await container.wait();
      exitCode = result.StatusCode;

      const executionTime = (Date.now() - startTime) / 1000;

      return {
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        exitCode,
        executionTime,
        memoryUsed: memoryLimit,
        timedOut,
        compilationError: exitCode !== 0 && stderr ? stderr : undefined
      };

    } catch (error: any) {
      if (timedOut) {
        return {
          stdout: stdout.trim(),
          stderr: 'Execution timed out',
          exitCode: 124,
          executionTime: timeout,
          memoryUsed: 0,
          timedOut: true
        };
      }
      throw error;
    } finally {
      // Cleanup
      if (container) {
        try {
          await container.remove({ force: true });
        } catch (e) {
          console.error('Container removal error:', e);
        }
      }
      await this.cleanupWorkspace(workDir);
    }
  }

  private async prepareWorkspace(dir: string, config: ExecutionConfig): Promise<void> {
    await fs.mkdir(dir, { recursive: true });
    
    const extension = this.extensionMap.get(config.language) || '.txt';
    let filename = 'main' + extension;
    
    if (config.language === 'java') {
      filename = 'Main.java';
    }
    
    await fs.writeFile(path.join(dir, filename), config.code);
  }

  private async cleanupWorkspace(dir: string): Promise<void> {
    try {
      await fs.rm(dir, { recursive: true, force: true });
    } catch (e) {
      console.error('Workspace cleanup error:', e);
    }
  }

  private async ensureImage(image: string): Promise<void> {
    try {
      await this.docker.getImage(image).inspect();
    } catch (error) {
      console.log(`Pulling image: ${image}`);
      await new Promise((resolve, reject) => {
        this.docker.pull(image, (err: any, stream: any) => {
          if (err) return reject(err);
          this.docker.modem.followProgress(stream, (err: any, output: any) => {
            if (err) return reject(err);
            resolve(output);
          });
        });
      });
    }
  }
}

// ============================================================================
// FILE: src/services/executionQueue.ts
// Job queue for code execution
// ============================================================================

import Queue from 'bull';
import { config } from '../config';
import { DockerExecutor, ExecutionConfig, ExecutionResult } from './dockerExecutor';
import { io } from '../server';
import { db } from '../db';

interface ExecutionJob {
  executionId: string;
  userId: string;
  config: ExecutionConfig;
}

export const executionQueue = new Queue<ExecutionJob>('code-execution', config.redis.url);

// Process execution jobs
executionQueue.process(async (job) => {
  const { executionId, userId, config: execConfig } = job.data;
  const executor = new DockerExecutor();

  try {
    // Update status to running
    await db.execution.update({
      where: { id: executionId },
      data: {
        status: 'RUNNING',
        startedAt: new Date()
      }
    });

    // Emit status via WebSocket
    io.to(`execution:${executionId}`).emit('execution:status', {
      executionId,
      status: 'running',
      timestamp: new Date()
    });

    // Execute code
    const result: ExecutionResult = await executor.execute(execConfig);

    // Store result in database
    await db.execution.update({
      where: { id: executionId },
      data: {
        status: result.timedOut ? 'TIMEOUT' : 'COMPLETED',
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.exitCode,
        executionTimeMs: Math.round(result.executionTime * 1000),
        memoryUsedMb: result.memoryUsed,
        timedOut: result.timedOut,
        compilationError: result.compilationError,
        completedAt: new Date()
      }
    });

    // Update user quota
    await db.userQuota.upsert({
      where: { userId },
      update: {
        executionsToday: { increment: 1 },
        executionsMonth: { increment: 1 }
      },
      create: {
        userId,
        executionsToday: 1,
        executionsMonth: 1
      }
    });

    // Emit completion via WebSocket
    io.to(`execution:${executionId}`).emit('execution:complete', {
      executionId,
      result,
      timestamp: new Date()
    });

    return result;

  } catch (error: any) {
    // Update status to failed
    await db.execution.update({
      where: { id: executionId },
      data: {
        status: 'FAILED',
        stderr: error.message,
        completedAt: new Date()
      }
    });

    // Emit error via WebSocket
    io.to(`execution:${executionId}`).emit('execution:error', {
      executionId,
      error: error.message,
      timestamp: new Date()
    });

    throw error;
  }
});

// Job event handlers
executionQueue.on('completed', (job, result) => {
  console.log(`✓ Execution ${job.data.executionId} completed`);
});

executionQueue.on('failed', (job, err) => {
  console.error(`✗ Execution ${job?.data?.executionId} failed:`, err.message);
});

export async function queueExecution(
  executionId: string,
  userId: string,
  config: ExecutionConfig
): Promise<void> {
  await executionQueue.add({
    executionId,
    userId,
    config
  }, {
    attempts: 1,
    timeout: (config.timeout || 30) * 1000 + 5000,
    removeOnComplete: true,
    removeOnFail: false
  });
}

// ============================================================================
// FILE: src/routes/execute.routes.ts
// Execution API routes
// ============================================================================

import { Router } from 'express';
import { authenticateJWT, AuthRequest } from '../middleware/auth';
import { executionLimiter } from '../middleware/rateLimiter';
import { queueExecution } from '../services/executionQueue';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { config } from '../config';

const router = Router();

// POST /api/v1/execute
router.post('/', authenticateJWT, executionLimiter, async (req: AuthRequest, res, next) => {
  try {
    const { language, code, stdin, timeout, memoryLimit } = req.body;

    // Validation
    if (!language || !code) {
      throw new AppError('Language and code are required', 400);
    }

    if (code.length > config.execution.maxCodeLength) {
      throw new AppError(`Code exceeds maximum length of ${config.execution.maxCodeLength} characters`, 400);
    }

    // Check user quota
    const quota = await db.userQuota.findUnique({
      where: { userId: req.user!.userId }
    });

    if (quota && quota.executionsToday >= quota.maxExecutionsDaily) {
      throw new AppError('Daily execution limit reached', 429);
    }

    // Create execution record
    const execution = await db.execution.create({
      data: {
        userId: req.user!.userId,
        language,
        status: 'QUEUED',
        stdin: stdin || null
      }
    });

    // Queue execution
    await queueExecution(execution.id, req.user!.userId, {
      language,
      code,
      stdin,
      timeout,
      memoryLimit
    });

    res.status(200).json({
      success: true,
      data: {
        executionId: execution.id,
        status: 'queued',
        estimatedTime: 2
      }
    });

  } catch (error) {
    next(error);
  }
});

// GET /api/v1/execute/:executionId
router.get('/:executionId', authenticateJWT, async (req: AuthRequest, res, next) => {
  try {
    const { executionId } = req.params;

    const execution = await db.execution.findUnique({
      where: { id: executionId }
    });

    if (!execution) {
      throw new AppError('Execution not found', 404);
    }

    if (execution.userId !== req.user!.userId) {
      throw new AppError('Unauthorized', 403);
    }

    res.json({
      success: true,
      data: {
        executionId: execution.id,
        status: execution.status.toLowerCase(),
        output: execution.stdout || '',
        error: execution.stderr || '',
        executionTime: execution.executionTimeMs ? execution.executionTimeMs / 1000 : null,
        memoryUsed: execution.memoryUsedMb || null,
        exitCode: execution.exitCode,
        compilationError: execution.compilationError,
        timedOut: execution.timedOut,
        createdAt: execution.createdAt,
        completedAt: execution.completedAt
      }
    });

  } catch (error) {
    next(error);
  }
});

export default router;
