import { readFile } from "node:fs/promises";

export async function readUserFile(userPath) {
  // Intentionally vulnerable benchmark: no root-containment check.
  return readFile(userPath, "utf8");
}

export async function fetchUserUrl(url) {
  const response = await fetch(url);
  return response.text();
}
