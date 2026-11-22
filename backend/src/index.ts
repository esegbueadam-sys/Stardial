import "reflect-metadata";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import swaggerUi from "swagger-ui-express";
import { healthRouter, markStartupComplete, markShuttingDown } from "./routes/health.js";
import { opsRouter } from "./routes/ops.js";
import { isMetricsEnabled, metricsRouter } from "./routes/metrics.js";
import { splitsRouter } from "./routes/splits.js";
import { docsRouter } from "./routes/docs.js";
import { usersRouter } from "./routes/users.js";
import { authEmailRouter } from "./routes/auth-email.js";
import { authAccountRouter } from "./routes/auth-account.js";
import { collaborationRouter } from "./routes/collaboration.js";
import { transactionsRouter } from "./routes/transactions.js";
import { eventsRouter, closeAllSseConnections } from "./routes/events.js";
import { ledgerRouter } from "./routes/ledger.js";
import { notificationsRouter } from "./routes/notifications.js";
import { webhooksRouter } from "./routes/webhooks.js";
import { errorHandler, notFoundHandler } from "./middleware/error.js";
import { requestIdMiddleware } from "./middleware/request-id.js";
import { idempotentMutations } from "./middleware/idempotency.js";
import {
  metricsMiddleware,
  payloadSizeMetricsMiddleware,
  splitLifecycleMetricsMiddleware,
} from "./middleware/metrics.js";
import { requestTimeout } from "./middleware/timeout.js";
import {
  globalLimiter,
  readLimiter,
  writeLimiter,
  adminLimiter,
  authLimiter,
  sseConnectionLimiter,
} from "./middleware/rate-limit.js";
import {
  enforcePaymentsAdminWriteEnabled,
  requirePaymentsAdminAccess,
} from "./middleware/payments-admin.js";
import { auditAdminMutationsMiddleware } from "./middleware/audit-log.js";
import { validateEnv, printEnvDiagnostics } from "./config/env.js";
import { resolveCorsOrigins } from "./config/cors.js";
import { initDatabase, closeDatabase } from "./services/database.js";
import { logger } from "./services/logger.js";
import {
  startEventListenerService,
  stopEventListenerService,
} from "./services/EventListenerService.js";

dotenv.config();

export const app = express();

app.disable("x-powered-by");

const corsOrigin = resolveCorsOrigins(process.env);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    frameguard: { action: "deny" },
    xssFilter: true,
    noSniff: true,
  })
);
// Auth uses bearer tokens, not cookies. Still allow the bearer header and
// request-correlation header explicitly, and expose request IDs to browsers.
app.use(
  cors({
    origin: corsOrigin,
    credentials: false,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Authorization",
      "Content-Type",
      "X-Request-ID",
      "Idempotency-Key",
      "X-Webhook-Signature",
      "X-Webhook-Timestamp",
      "X-Webhook-Id",
      "X-Delivery-Id",
      "X-Event-Id",
    ],
    exposedHeaders: ["X-Request-ID", "Retry-After"],
  })
);
// Before express.json() so 413 rejections are still counted (Issue #1090).
app.use(payloadSizeMetricsMiddleware);
app.use(splitLifecycleMetricsMiddleware);
app.use(
  express.json({
    limit: "1mb",
    verify: (req, _res, body) => {
      (req as express.Request & { rawBody?: Buffer }).rawBody = Buffer.from(body);
    },
  })
);
app.use(requestIdMiddleware);
app.use(express.json({ limit: "1mb" }));
// Issue #17: retries must not duplicate writes. Mounted once for every
// mutation method so new routes are covered by default. Opt-in via the
// `Idempotency-Key` header, so behaviour is unchanged for existing clients.
app.use(idempotentMutations());
app.use(metricsMiddleware);
app.use(requestTimeout());

app.use(globalLimiter);

// Per-endpoint limits are applied below; log all rejected (429) requests for monitoring.
app.use((_req, res, next) => {
  res.on("finish", () => {
    if (res.statusCode === 429) {
      logger.warn("Rate limit rejected request", {
        method: _req.method,
        path: _req.originalUrl,
        ip: _req.ip,
        requestId: res.locals.requestId ?? _req.header("x-request-id") ?? "-",
      });
    }
  });
  next();
});

app.use("/docs", (_req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
  );
  next();
});

const WALLET_ADDRESS_REGEX = /\b[GC][A-Z2-7]{55}\b/g;

export function scrubWalletAddresses(value: string): string {
  return value.replace(WALLET_ADDRESS_REGEX, "[WALLET_REDACTED]");
}

app.use(
  morgan((tokens, req, res) => {
    const requestId = res.locals.requestId ?? req.header("x-request-id") ?? "-";
    return [
      tokens.method(req, res),
      scrubWalletAddresses(tokens.url(req, res) ?? ""),
      tokens.status(req, res),
      "-",
      tokens["response-time"](req, res),
      "ms",
      "x-request-id=",
      String(requestId),
    ].join(" ");
  })
);

app.use("/health", readLimiter);
app.use(
  "/splits/admin",
  adminLimiter,
  auditAdminMutationsMiddleware,
  requirePaymentsAdminAccess,
  enforcePaymentsAdminWriteEnabled
);
app.use("/splits", (req, res, next) => {
  if (req.method === "GET") return readLimiter(req, res, next);
  return writeLimiter(req, res, next);
});
app.use("/users/register", authLimiter);
app.use("/users/login", authLimiter);
app.use("/auth", authLimiter);
app.use("/users", (req, res, next) => {
  if (req.method === "GET") return readLimiter(req, res, next);
  return writeLimiter(req, res, next);
});
app.use("/transactions", readLimiter);
app.use("/notifications", readLimiter);
app.use("/api/ledger", readLimiter);
app.use("/events", sseConnectionLimiter);

app.get("/", (_req, res) => {
  res.json({ name: "Stardial API", status: "ok", version: "0.1.0" });
});

app.use("/health", healthRouter);
if (isMetricsEnabled()) {
  app.use("/metrics", metricsRouter);
}
app.use("/splits", splitsRouter);
app.use("/ops", opsRouter);
app.use("/docs", docsRouter);
app.use("/auth", authEmailRouter);
app.use("/auth", authAccountRouter);
app.use("/collaboration", collaborationRouter);
app.use("/users", usersRouter);
app.use("/transactions", transactionsRouter);
app.use("/events", eventsRouter);
app.use("/api/ledger", ledgerRouter);
app.use("/notifications", notificationsRouter);
app.use("/webhooks", webhooksRouter);
app.use("/v1/webhooks", webhooksRouter);

app.get("/api/openapi.json", async (_req, res, next) => {
  try {
    const { generateOpenApi } = await import("./openapi.js");
    const spec = generateOpenApi();
    res.json(spec);
  } catch (error) {
    next(error);
  }
});

const swaggerOptions = {
  customCss: ".swagger-ui .topbar { display: none }",
  customSiteTitle: "Stardial API Documentation",
  swaggerOptions: {
    url: "/api/openapi.json",
    displayOperationId: true,
    filter: true,
    showExtensions: true,
  },
};

app.use("/api/docs", swaggerUi.serve, swaggerUi.setup(null, swaggerOptions));
app.get("/api/docs/", (_req, res) => {
  res.redirect("/api/docs");
});

app.use(notFoundHandler);
app.use(errorHandler);

async function initSentry(): Promise<void> {
  if (!process.env.SENTRY_DSN) return;
  const Sentry = await import("@sentry/node");
  const scrubWallets = process.env.SENTRY_SCRUB_WALLET_ADDRESSES !== "false";
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.SENTRY_ENVIRONMENT ?? process.env.NODE_ENV ?? "development",
    release: process.env.npm_package_version,
    beforeSend(event) {
      if (scrubWallets) {
        const scrubbed = JSON.stringify(event).replace(
          /\b[GC][A-Z2-7]{55}\b/g,
          "[WALLET_REDACTED]"
        );
        return JSON.parse(scrubbed);
      }
      return event;
    },
  });
}

async function captureToSentry(err: unknown): Promise<void> {
  if (!process.env.SENTRY_DSN) return;
  const Sentry = await import("@sentry/node");
  Sentry.captureException(err);
}

if (process.env.NODE_ENV !== "test") {
  const start = async () => {
    try {
      await initSentry();
      if (process.env.NODE_ENV !== "production") {
        printEnvDiagnostics();
      }
      validateEnv();
      await initDatabase();
      await startEventListenerService();
      markStartupComplete();

      const port = Number(process.env.PORT ?? 3001);
      const server = app.listen(port, () => {
        logger.info(`Server started on port ${port}`);
      });

      const shutdown = async (signal: NodeJS.Signals) => {
        logger.info(`Received ${signal}. Shutting down...`);
        // Flip readiness first so load balancers stop routing new traffic
        // here immediately, well before DB/SSE/server teardown finishes.
        markShuttingDown();
        closeAllSseConnections();
        stopEventListenerService();
        await closeDatabase();
        server.close((err?: Error) => {
          if (err) {
            logger.error("Error during server close", { error: err });
            process.exit(1);
          }
          logger.info("Server closed cleanly");
          process.exit(0);
        });
        const forceTimeoutMs = Number(process.env.SHUTDOWN_FORCE_TIMEOUT_MS ?? 10_000);
        setTimeout(() => {
          logger.warn("Force exiting after timeout");
          process.exit(1);
        }, forceTimeoutMs).unref();
      };

      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);

      process.on("unhandledRejection", (reason) => {
        logger.error("Unhandled promise rejection", { reason });
        void captureToSentry(reason);
        process.exit(1);
      });
      process.on("uncaughtException", (err) => {
        logger.error("Uncaught exception", { error: err });
        void captureToSentry(err);
        process.exit(1);
      });
    } catch (err) {
      logger.error("Failed to start server", { error: err });
      void captureToSentry(err);
      process.exit(1);
    }
  };
  void start();
}
