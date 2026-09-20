import { DnsClient } from "./dns-client.js";

export class DiagnosticsService {
  constructor(client = new DnsClient()) {
    this.client = client;
  }

  resolve(host, callback) {
    const normalized = host.trim();
    if (!normalized) throw new Error("a host is required");
    this.client.lookup(normalized, callback);
  }
}
