import { execFile } from "node:child_process";
export function inspectHost(host, callback) {
  execFile("nslookup", [host], callback);
}
