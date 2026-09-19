import { DiagnosticsService } from "./diagnostics-service.js";

class DiagnosticsEndpoint {
  constructor(service = new DiagnosticsService()) {
    this.service = service;
  }

  inspect(host, callback) {
    this.service.resolve(host, callback);
  }
}

export function inspectHost(host, callback) {
  new DiagnosticsEndpoint().inspect(host, callback);
}
