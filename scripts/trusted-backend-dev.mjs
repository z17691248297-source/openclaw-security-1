#!/usr/bin/env node

import { startTrustedBackendServer } from "../external/openclaw-trusted-backend/server.mjs";

void startTrustedBackendServer().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
