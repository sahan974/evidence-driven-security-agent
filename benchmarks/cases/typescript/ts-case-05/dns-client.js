import { execFile } from "node:child_process";

export class DnsClient {
  lookup(host, callback) {
    execFile("nslookup", [host], callback);
  }
}
