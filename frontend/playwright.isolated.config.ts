import { defineConfig } from "@playwright/test";
import base from "./playwright.config";

export default defineConfig({ ...base, testIgnore: "passwordless.spec.ts", use: { ...base.use, baseURL: "http://127.0.0.1:5175", video: "off" } });
