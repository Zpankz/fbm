#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const command = process.argv[2];
const ctx = JSON.parse(process.argv[3] || "{}");
const payload = JSON.parse(process.argv[4] || "{}");

function emit(commandName, data, ok = true) {
  process.stdout.write(JSON.stringify({ ok, command: commandName, data }) + "\n");
}

function serializeError(err) {
  if (!err) return { message: "unknown error" };
  return {
    message: err.message || String(err),
    name: err.name,
    code: err.code,
    stack: process.env.FBM_DEBUG ? err.stack : undefined,
    originalError: err.originalError ? serializeError(err.originalError) : undefined,
  };
}

function normalizeMessage(message, fallbackThreadID) {
  const now = String(Date.now());
  const m = message || {};
  return {
    ...m,
    type: m.type || "message",
    messageID: String(m.messageID || m.message_id || m.offlineThreadingID || `${fallbackThreadID || "unknown"}-${Date.now()}`),
    threadID: String(m.threadID || m.thread_id || fallbackThreadID || ""),
    senderID: m.senderID ? String(m.senderID) : (m.author ? String(m.author) : undefined),
    body: m.body || "",
    timestamp: m.timestamp ? String(m.timestamp) : now,
    attachments: Array.isArray(m.attachments) ? m.attachments : [],
    mentions: m.mentions || {},
  };
}

function normalizeThread(thread) {
  return {
    ...thread,
    threadID: String(thread.threadID),
    threadName: thread.threadName || thread.name || null,
    participantIDs: (thread.participantIDs || []).map(String),
    userInfo: thread.userInfo || [],
    timestamp: thread.timestamp ? String(thread.timestamp) : (thread.updated_time_precise ? String(thread.updated_time_precise) : undefined),
  };
}

function loadApi() {
  if (!ctx.fcaDir) throw new Error("missing fcaDir in bridge context");
  if (!ctx.appstate) throw new Error("missing appstate in bridge context");
  const fcaDir = path.resolve(ctx.fcaDir);
  const modulePath = path.join(fcaDir, "module", "index.js");
  const appstatePath = path.resolve(ctx.appstate);
  const { login } = require(modulePath);
  const appState = JSON.parse(fs.readFileSync(appstatePath, "utf8"));
  return new Promise((resolve, reject) => {
    login({ appState }, ctx.options || {}, (err, api) => {
      if (err) return reject(err);
      resolve(api);
    });
  });
}

async function main() {
  try {
    if (!command) throw new Error("missing bridge command");
    const api = await loadApi();

    if (command === "me") {
      emit("me", { userID: api.getCurrentUserID(), appStateKeys: (api.getAppState() || []).map((c) => c.key).filter(Boolean) });
      return;
    }

    if (command === "threads") {
      const limit = Number(payload.limit || 50);
      const timestamp = payload.timestamp == null ? null : Number(payload.timestamp);
      const tags = payload.tags || ["INBOX"];
      const threads = await api.getThreadList(limit, timestamp, tags);
      emit("threads", (threads || []).filter(Boolean).map(normalizeThread));
      return;
    }

    if (command === "history") {
      const threadID = String(payload.threadID || payload.threadId || "");
      if (!threadID) throw new Error("history requires threadID");
      const amount = Number(payload.amount || payload.limit || 100);
      const timestamp = payload.timestamp == null ? null : Number(payload.timestamp);
      const messages = await api.getThreadHistory(threadID, amount, timestamp);
      emit("history", (messages || []).map((m) => normalizeMessage(m, threadID)));
      return;
    }

    if (command === "send") {
      const threadID = String(payload.threadID || payload.threadId || "");
      const body = String(payload.body || "");
      if (!threadID) throw new Error("send requires threadID");
      if (!body) throw new Error("send requires body");
      const result = await api.sendMessageMqtt(body, threadID, payload.replyTo || undefined);
      emit("send", normalizeMessage({ ...result, body, senderID: api.getCurrentUserID() }, threadID));
      return;
    }

    if (command === "listen") {
      emit("ready", { userID: api.getCurrentUserID() });
      await api.listenMqtt((err, event) => {
        if (err) {
          emit("error", serializeError(err), false);
          return;
        }
        if (!event) return;
        if (event.type === "message" || event.type === "message_reply") {
          emit("event", normalizeMessage(event, event.threadID));
        } else {
          emit("event", event);
        }
      });
      // Keep process alive for MQTT callbacks.
      setInterval(() => {}, 1 << 30);
      return;
    }

    throw new Error(`unknown bridge command: ${command}`);
  } catch (err) {
    emit(command || "unknown", serializeError(err), false);
    process.exitCode = 1;
  }
}

main();
