import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

const root = resolve("documents");

export class DocumentStore {
  async readText(name) {
    const target = resolve(root, name);
    if (!target.startsWith(root + sep)) throw new Error("outside root");
    return readFile(target, "utf8");
  }
}
