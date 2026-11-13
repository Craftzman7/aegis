import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { generateKeyPairSync } from "node:crypto";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  const migrations = await readD1Migrations("./migrations");
  const jwk = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./test/wrangler.test.jsonc" },
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            SIGNING_KEY_JWK: JSON.stringify({ kty: jwk.kty, crv: jwk.crv, d: jwk.d, x: jwk.x }),
            DEV_MODE: "true",
          },
        },
      }),
    ],
    test: { setupFiles: ["./test/setup.ts"], testTimeout: 20000 },
  };
});
