/**
 * Mutation-wide idempotency coverage (Issue #17).
 *
 * Retries used to be deduplicated only on the routes that happened to mount
 * `idempotencyMiddleware()` by hand (create split, deposit). `idempotentMutations`
 * is mounted once before the routers so every write method honours the
 * `Idempotency-Key` contract, and stacked route-level guards no longer race
 * each other into a spurious in-flight 409.
 */
import express, { type Request, type Response } from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";

import { idempotencyMiddleware, idempotentMutations } from "../idempotency.js";
import { requestIdMiddleware } from "../request-id.js";
import { errorHandler, notFoundHandler } from "../error.js";
import { IdempotencyStore } from "../../services/idempotency.js";

const KEY = "mutation-key";

let store: IdempotencyStore;
let handler: Mock<(req: Request, res: Response) => unknown>;

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(requestIdMiddleware);
  app.use(idempotentMutations(store));

  app.post("/items", (req, res) => handler(req, res));
  app.put("/items/:id", (req, res) => handler(req, res));
  app.patch("/items/:id", (req, res) => handler(req, res));
  app.delete("/items/:id", (req, res) => handler(req, res));
  app.get("/items", (req, res) => handler(req, res));

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

beforeEach(() => {
  store = new IdempotencyStore();
  handler = vi.fn((_req: Request, res: Response) => {
    res.status(201).json({ id: "item-1" });
  });
});

describe("idempotentMutations (Issue #17)", () => {
  it("replays a retried POST instead of executing it twice", async () => {
    const app = createApp();

    const first = await request(app).post("/items").set("Idempotency-Key", KEY).send({ a: 1 });
    const retry = await request(app).post("/items").set("Idempotency-Key", KEY).send({ a: 1 });

    expect(first.status).toBe(201);
    expect(retry.body).toEqual(first.body);
    expect(retry.headers["idempotency-replayed"]).toBe("true");
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it.each(["put", "patch", "delete"] as const)(
    "protects %s requests too",
    async (method) => {
      const app = createApp();

      await request(app)[method]("/items/7").set("Idempotency-Key", KEY).send({ a: 1 });
      const retry = await request(app)
        .post("/items")
        .set("Idempotency-Key", "unrelated")
        .send({ a: 2 });
      expect(retry.status).toBe(201);

      const replay = await request(app)[method]("/items/7").set("Idempotency-Key", KEY).send({ a: 1 });

      expect(replay.headers["idempotency-replayed"]).toBe("true");
      // two handlers: the PUT/PATCH/DELETE once and the unrelated POST once.
      expect(handler).toHaveBeenCalledTimes(2);
    },
  );

  it("leaves read-only requests untouched", async () => {
    const app = createApp();

    const first = await request(app).get("/items").set("Idempotency-Key", KEY);
    const second = await request(app).get("/items").set("Idempotency-Key", KEY);

    expect(first.headers["idempotency-status"]).toBeUndefined();
    expect(second.headers["idempotency-status"]).toBeUndefined();
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it("passes requests without an Idempotency-Key straight through", async () => {
    const app = createApp();

    await request(app).post("/items").send({ a: 1 }).expect(201);
    await request(app).post("/items").send({ a: 1 }).expect(201);

    expect(handler).toHaveBeenCalledTimes(2);
  });

  it("does not treat a route-level guard as an in-flight duplicate", async () => {
    const app = express();
    app.use(express.json());
    app.use(requestIdMiddleware);
    app.use(idempotentMutations(store));
    app.post("/nested", idempotencyMiddleware(store), (req, res) => handler(req, res));
    app.use(notFoundHandler);
    app.use(errorHandler);

    const first = await request(app).post("/nested").set("Idempotency-Key", KEY).send({ a: 1 });
    const retry = await request(app).post("/nested").set("Idempotency-Key", KEY).send({ a: 1 });

    expect(first.status).toBe(201);
    expect(retry.status).toBe(201);
    expect(retry.headers["idempotency-replayed"]).toBe("true");
    expect(handler).toHaveBeenCalledTimes(1);
  });
});
