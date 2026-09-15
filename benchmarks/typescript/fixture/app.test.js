import assert from "node:assert/strict";
import test from "node:test";

import { readUserFile } from "./app.js";

test("reads a file inside the application directory", async () => {
  assert.equal(await readUserFile("safe.txt"), "safe benchmark content\n");
});
