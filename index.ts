// ============================================================================
// FILE: src/db/index.ts
// Prisma database client
// ============================================================================

import { PrismaClient } from '@prisma/client';

export const db = new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error']
});

// Graceful shutdown
process.on('beforeExit', async () => {
  await db.$disconnect();
});

// ============================================================================
// FILE: prisma/schema.prisma
// Database schema
// ============================================================================

/*
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id            String    @id @default(uuid())
  email         String    @unique
  username      String    @unique
  passwordHash  String    @map("password_hash")
  fullName      String?   @map("full_name")
  avatarUrl     String?   @map("avatar_url")
  emailVerified Boolean   @default(false) @map("email_verified")
  isActive      Boolean   @default(true) @map("is_active")
  role          UserRole  @default(USER)
  createdAt     DateTime  @default(now()) @map("created_at")
  updatedAt     DateTime  @updatedAt @map("updated_at")
  lastLoginAt   DateTime? @map("last_login_at")

  projects      Project[]
  executions    Execution[]
  refreshTokens RefreshToken[]
  quota         UserQuota?

  @@map("users")
}

enum UserRole {
  USER
  ADMIN
  MODERATOR
}

model RefreshToken {
  id        String   @id @default(uuid())
  userId    String   @map("user_id")
  token     String   @unique
  expiresAt DateTime @map("expires_at")
  createdAt DateTime @default(now()) @map("created_at")
  revoked   Boolean  @default(false)
  ipAddress String?  @map("ip_address")
  userAgent String?  @map("user_agent")

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("refresh_tokens")
}

model Project {
  id          String      @id @default(uuid())
  userId      String      @map("user_id")
  name        String
  description String?
  language    String
  visibility  Visibility  @default(PRIVATE)
  isTemplate  Boolean     @default(false) @map("is_template")
  createdAt   DateTime    @default(now()) @map("created_at")
  updatedAt   DateTime    @updatedAt @map("updated_at")
  deletedAt   DateTime?   @map("deleted_at")

  user       User        @relation(fields: [userId], references: [id], onDelete: Cascade)
  files      File[]
  executions Execution[]

  @@index([userId])
  @@map("projects")
}

enum Visibility {
  PRIVATE
  PUBLIC
  UNLISTED
}

model File {
  id        String   @id @default(uuid())
  projectId String   @map("project_id")
  name      String
  path      String   @default("/")
  content   String?
  sizeBytes BigInt   @default(0) @map("size_bytes")
  language  String?
  isMain    Boolean  @default(false) @map("is_main")
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @updatedAt @map("updated_at")

  project Project @relation(fields: [projectId], references: [id], onDelete: Cascade)

  @@unique([projectId, path, name])
  @@map("files")
}

model Execution {
  id               String       @id @default(uuid())
  userId           String       @map("user_id")
  projectId        String?      @map("project_id")
  language         String
  status           ExecStatus   @default(QUEUED)
  stdin            String?
  stdout           String?
  stderr           String?
  exitCode         Int?         @map("exit_code")
  executionTimeMs  Int?         @map("execution_time_ms")
  memoryUsedMb     Decimal?     @map("memory_used_mb") @db.Decimal(10, 2)
  timedOut         Boolean      @default(false) @map("timed_out")
  compilationError String?      @map("compilation_error")
  createdAt        DateTime     @default(now()) @map("created_at")
  startedAt        DateTime?    @map("started_at")
  completedAt      DateTime?    @map("completed_at")

  user    User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  project Project? @relation(fields: [projectId], references: [id], onDelete: SetNull)

  @@index([userId])
  @@map("executions")
}

enum ExecStatus {
  QUEUED
  RUNNING
  COMPLETED
  FAILED
  TIMEOUT
}

model UserQuota {
  userId             String   @id @map("user_id")
  executionsToday    Int      @default(0) @map("executions_today")
  executionsMonth    Int      @default(0) @map("executions_month")
  storageUsedMb      Decimal  @default(0) @map("storage_used_mb") @db.Decimal(10, 2)
  maxExecutionsDaily Int      @default(100) @map("max_executions_daily")
  maxExecutionsMonthly Int    @default(1000) @map("max_executions_monthly")
  maxStorageMb       Int      @default(100) @map("max_storage_mb")
  lastResetDaily     DateTime @default(now()) @map("last_reset_daily") @db.Date
  lastResetMonthly   DateTime @default(now()) @map("last_reset_monthly") @db.Date
  updatedAt          DateTime @updatedAt @map("updated_at")

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("user_quotas")
}
*/

// ============================================================================
// FILE: src/routes/auth.routes.ts
// Authentication routes
// ============================================================================

import { Router } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { db } from '../db';
import { config } from '../config';
import { authLimiter } from '../middleware/rateLimiter';
import { AppError } from '../middleware/errorHandler';
import { authenticateJWT, AuthRequest } from '../middleware/auth';

const router = Router();

// POST /api/v1/auth/register
router.post('/register', authLimiter, async (req, res, next) => {
  try {
    const { email, password, username, fullName } = req.body;

    // Validation
    if (!email || !password || !username) {
      throw new AppError('Email, password, and username are required', 400);
    }

    if (password.length < 8) {
      throw new AppError('Password must be at least 8 characters', 400);
    }

    // Check if user exists
    const existingUser = await db.user.findFirst({
      where: {
        OR: [{ email }, { username }]
      }
    });

    if (existingUser) {
      throw new AppError('Email or username already exists', 409);
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // Create user
    const user = await db.user.create({
      data: {
        email,
        username,
        passwordHash,
        fullName
      }
    });

    // Generate tokens
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        username: user.username,
        role: user.role
      },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );

    const refreshToken = jwt.sign(
      { userId: user.id },
      config.jwt.refreshSecret,
      { expiresIn: config.jwt.refreshExpiresIn }
    );

    // Store refresh token
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await db.refreshToken.create({
      data: {
        userId: user.id,
        token: refreshToken,
        expiresAt,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      }
    });

    res.status(201).json({
      success: true,
      data: {
        userId: user.id,
        token,
        refreshToken,
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          fullName: user.fullName
        }
      }
    });

  } catch (error) {
    next(error);
  }
});

// POST /api/v1/auth/login
router.post('/login', authLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      throw new AppError('Email and password are required', 400);
    }

    // Find user
    const user = await db.user.findUnique({
      where: { email }
    });

    if (!user || !user.isActive) {
      throw new AppError('Invalid credentials', 401);
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);

    if (!isValidPassword) {
      throw new AppError('Invalid credentials', 401);
    }

    // Generate tokens
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        username: user.username,
        role: user.role
      },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );

    const refreshToken = jwt.sign(
      { userId: user.id },
      config.jwt.refreshSecret,
      { expiresIn: config.jwt.refreshExpiresIn }
    );

    // Store refresh token
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await db.refreshToken.create({
      data: {
        userId: user.id,
        token: refreshToken,
        expiresAt,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      }
    });

    // Update last login
    await db.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() }
    });

    res.json({
      success: true,
      data: {
        token,
        refreshToken,
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          fullName: user.fullName
        }
      }
    });

  } catch (error) {
    next(error);
  }
});

// POST /api/v1/auth/refresh
router.post('/refresh', async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      throw new AppError('Refresh token is required', 400);
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, config.jwt.refreshSecret) as any;

    // Check if token exists and is not revoked
    const storedToken = await db.refreshToken.findFirst({
      where: {
        token: refreshToken,
        userId: decoded.userId,
        revoked: false,
        expiresAt: {
          gt: new Date()
        }
      },
      include: {
        user: true
      }
    });

    if (!storedToken) {
      throw new AppError('Invalid or expired refresh token', 401);
    }

    // Generate new access token
    const newToken = jwt.sign(
      {
        userId: storedToken.user.id,
        email: storedToken.user.email,
        username: storedToken.user.username,
        role: storedToken.user.role
      },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );

    res.json({
      success: true,
      data: {
        token: newToken
      }
    });

  } catch (error) {
    next(error);
  }
});

// POST /api/v1/auth/logout
router.post('/logout', authenticateJWT, async (req: AuthRequest, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (refreshToken) {
      // Revoke refresh token
      await db.refreshToken.updateMany({
        where: {
          token: refreshToken,
          userId: req.user!.userId
        },
        data: {
          revoked: true
        }
      });
    }

    res.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    next(error);
  }
});

export default router;

// ============================================================================
// FILE: src/websocket/server.ts
// WebSocket server implementation
// ============================================================================

import { Server } from 'socket.io';
import jwt from 'jsonwebtoken';
import { config } from '../config';

interface SocketUser {
  userId: string;
  username: string;
  email: string;
}

declare module 'socket.io' {
  interface Socket {
    user?: SocketUser;
  }
}

export function setupWebSocket(httpServer: any) {
  const io = new Server(httpServer, {
    cors: {
      origin: config.cors.origin,
      credentials: true
    },
    path: '/ws',
    transports: ['websocket', 'polling']
  });

  // Authentication middleware
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth.token || 
                   socket.handshake.headers.authorization?.split(' ')[1];
      
      if (!token) {
        return next(new Error('Authentication required'));
      }

      const decoded = jwt.verify(token, config.jwt.secret) as any;
      socket.user = {
        userId: decoded.userId,
        username: decoded.username,
        email: decoded.email
      };
      
      next();
    } catch (error) {
      next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    console.log(`✓ User connected: ${socket.user?.username} (${socket.id})`);

    // Join user's personal room
    socket.join(`user:${socket.user?.userId}`);

    // Subscribe to execution updates
    socket.on('subscribe:execution', (executionId: string) => {
      socket.join(`execution:${executionId}`);
      console.log(`  → User subscribed to execution: ${executionId}`);
    });

    socket.on('unsubscribe:execution', (executionId: string) => {
      socket.leave(`execution:${executionId}`);
      console.log(`  → User unsubscribed from execution: ${executionId}`);
    });

    // Join project room for collaboration
    socket.on('join:project', (projectId: string) => {
      socket.join(`project:${projectId}`);
      console.log(`  → User joined project: ${projectId}`);
      
      // Notify other users
      socket.to(`project:${projectId}`).emit('user:joined', {
        userId: socket.user?.userId,
        username: socket.user?.username
      });
    });

    socket.on('leave:project', (projectId: string) => {
      socket.leave(`project:${projectId}`);
      console.log(`  → User left project: ${projectId}`);
      
      // Notify other users
      socket.to(`project:${projectId}`).emit('user:left', {
        userId: socket.user?.userId,
        username: socket.user?.username
      });
    });

    // Real-time code updates (collaborative editing)
    socket.on('code:update', (data: {
      projectId: string;
      fileId: string;
      content: string;
      cursorPosition?: { line: number; column: number };
    }) => {
      // Broadcast to other users in the same project
      socket.to(`project:${data.projectId}`).emit('code:changed', {
        fileId: data.fileId,
        content: data.content,
        userId: socket.user?.userId,
        username: socket.user?.username,
        cursorPosition: data.cursorPosition,
        timestamp: new Date()
      });
    });

    // Cursor position updates
    socket.on('cursor:update', (data: {
      projectId: string;
      fileId: string;
      position: { line: number; column: number };
    }) => {
      socket.to(`project:${data.projectId}`).emit('cursor:moved', {
        fileId: data.fileId,
        userId: socket.user?.userId,
        username: socket.user?.username,
        position: data.position
      });
    });

    // Handle disconnection
    socket.on('disconnect', () => {
      console.log(`✗ User disconnected: ${socket.user?.username}`);
    });

    // Error handling
    socket.on('error', (error) => {
      console.error('Socket error:', error);
    });
  });

  // Helper function to emit to specific rooms
  io.emitToExecution = (executionId: string, event: string, data: any) => {
    io.to(`execution:${executionId}`).emit(event, data);
  };

  io.emitToUser = (userId: string, event: string, data: any) => {
    io.to(`user:${userId}`).emit(event, data);
  };

  io.emitToProject = (projectId: string, event: string, data: any) => {
    io.to(`project:${projectId}`).emit(event, data);
  };

  return io;
}

// Extend Server interface
declare module 'socket.io' {
  interface Server {
    emitToExecution(executionId: string, event: string, data: any): void;
    emitToUser(userId: string, event: string, data: any): void;
    emitToProject(projectId: string, event: string, data: any): void;
  }
}

// ============================================================================
// FILE: src/routes/project.routes.ts
// Project management routes
// ============================================================================

import { Router } from 'express';
import { authenticateJWT, AuthRequest } from '../middleware/auth';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';

const router = Router();

// GET /api/v1/projects
router.get('/', authenticateJWT, async (req: AuthRequest, res, next) => {
  try {
    const { page = '1', limit = '10', sort = 'updatedAt' } = req.query;
    const skip = (parseInt(page as string) - 1) * parseInt(limit as string);

    const [projects, total] = await Promise.all([
      db.project.findMany({
        where: {
          userId: req.user!.userId,
          deletedAt: null
        },
        include: {
          _count: {
            select: { files: true }
          }
        },
        orderBy: {
          [sort as string]: 'desc'
        },
        skip,
        take: parseInt(limit as string)
      }),
      db.project.count({
        where: {
          userId: req.user!.userId,
          deletedAt: null
        }
      })
    ]);

    res.json({
      success: true,
      data: {
        projects: projects.map(p => ({
          id: p.id,
          name: p.name,
          description: p.description,
          language: p.language,
          visibility: p.visibility,
          fileCount: p._count.files,
          createdAt: p.createdAt,
          updatedAt: p.updatedAt
        })),
        pagination: {
          total,
          page: parseInt(page as string),
          limit: parseInt(limit as string),
          pages: Math.ceil(total / parseInt(limit as string))
        }
      }
    });

  } catch (error) {
    next(error);
  }
});

// POST /api/v1/projects
router.post('/', authenticateJWT, async (req: AuthRequest, res, next) => {
  try {
    const { name, description, language, visibility = 'PRIVATE' } = req.body;

    if (!name || !language) {
      throw new AppError('Name and language are required', 400);
    }

    const project = await db.project.create({
      data: {
        userId: req.user!.userId,
        name,
        description,
        language,
        visibility
      }
    });

    res.status(201).json({
      success: true,
      data: {
        id: project.id,
        name: project.name,
        description: project.description,
        language: project.language,
        createdAt: project.createdAt
      }
    });

  } catch (error) {
    next(error);
  }
});

// GET /api/v1/projects/:projectId
router.get('/:projectId', authenticateJWT, async (req: AuthRequest, res, next) => {
  try {
    const { projectId } = req.params;

    const project = await db.project.findUnique({
      where: { id: projectId },
      include: {
        files: {
          orderBy: { createdAt: 'asc' }
        }
      }
    });

    if (!project || project.deletedAt) {
      throw new AppError('Project not found', 404);
    }

    if (project.userId !== req.user!.userId && project.visibility !== 'PUBLIC') {
      throw new AppError('Unauthorized', 403);
    }

    res.json({
      success: true,
      data: {
        id: project.id,
        name: project.name,
        description: project.description,
        language: project.language,
        visibility: project.visibility,
        files: project.files.map(f => ({
          id: f.id,
          name: f.name,
          path: f.path,
          content: f.content,
          sizeBytes: f.sizeBytes,
          isMain: f.isMain,
          createdAt: f.createdAt,
          updatedAt: f.updatedAt
        })),
        createdAt: project.createdAt,
        updatedAt: project.updatedAt
      }
    });

  } catch (error) {
    next(error);
  }
});

// PUT /api/v1/projects/:projectId
router.put('/:projectId', authenticateJWT, async (req: AuthRequest, res, next) => {
  try {
    const { projectId } = req.params;
    const { name, description, visibility } = req.body;

    const project = await db.project.findUnique({
      where: { id: projectId }
    });

    if (!project || project.deletedAt) {
      throw new AppError('Project not found', 404);
    }

    if (project.userId !== req.user!.userId) {
      throw new AppError('Unauthorized', 403);
    }

    const updated = await db.project.update({
      where: { id: projectId },
      data: {
        ...(name && { name }),
        ...(description !== undefined && { description }),
        ...(visibility && { visibility })
      }
    });

    res.json({
      success: true,
      data: updated
    });

  } catch (error) {
    next(error);
  }
});

// DELETE /api/v1/projects/:projectId
router.delete('/:projectId', authenticateJWT, async (req: AuthRequest, res, next) => {
  try {
    const { projectId } = req.params;

    const project = await db.project.findUnique({
      where: { id: projectId }
    });

    if (!project || project.deletedAt) {
      throw new AppError('Project not found', 404);
    }

    if (project.userId !== req.user!.userId) {
      throw new AppError('Unauthorized', 403);
    }

    // Soft delete
    await db.project.update({
      where: { id: projectId },
      data: { deletedAt: new Date() }
    });

    res.json({
      success: true,
      message: 'Project deleted successfully'
    });

  } catch (error) {
    next(error);
  }
});

export default router;

// ============================================================================
// FILE: src/routes/system.routes.ts
// System information routes
// ============================================================================

import { Router } from 'express';
import { authenticateJWT, AuthRequest } from '../middleware/auth';
import { db } from '../db';

const router = Router();

// GET /api/v1/languages
router.get('/languages', (req, res) => {
  const languages = [
    {
      id: 'python',
      name: 'Python',
      version: '3.11',
      extensions: ['.py'],
      available: true
    },
    {
      id: 'javascript',
      name: 'JavaScript (Node.js)',
      version: '20.x',
      extensions: ['.js'],
      available: true
    },
    {
      id: 'java',
      name: 'Java',
      version: '17',
      extensions: ['.java'],
      available: true
    },
    {
      id: 'cpp',
      name: 'C++',
      version: 'GCC 11',
      extensions: ['.cpp', '.cc', '.cxx'],
      available: true
    },
    {
      id: 'c',
      name: 'C',
      version: 'GCC 11',
      extensions: ['.c'],
      available: true
    },
    {
      id: 'php',
      name: 'PHP',
      version: '8.2',
      extensions: ['.php'],
      available: true
    }
  ];

  res.json({
    success: true,
    data: languages
  });
});

// GET /api/v1/stats
router.get('/stats', authenticateJWT, async (req: AuthRequest, res, next) => {
  try {
    const userId = req.user!.userId;

    const [projectCount, executionCount, quota] = await Promise.all([
      db.project.count({
        where: { userId, deletedAt: null }
      }),
      db.execution.count({
        where: { userId }
      }),
      db.userQuota.findUnique({
        where: { userId }
      })
    ]);

    const executions = await db.execution.findMany({
      where: {
        userId,
        createdAt: {
          gte: new Date(new Date().setHours(0, 0, 0, 0))
        }
      },
      select: {
        executionTimeMs: true
      }
    });

    const executionTimeToday = executions.reduce(
      (sum, e) => sum + (e.executionTimeMs || 0),
      0
    ) / 1000;

    res.json({
      success: true,
      data: {
        totalProjects: projectCount,
        totalExecutions: executionCount,
        executionsToday: quota?.executionsToday || 0,
        executionsMonth: quota?.executionsMonth || 0,
        storageUsed: Number(quota?.storageUsedMb || 0),
        executionTimeToday: Number(executionTimeToday.toFixed(2))
      }
    });

  } catch (error) {
    next(error);
  }
});

export default router;
