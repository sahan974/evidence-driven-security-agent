import { PreviewService } from "./preview-service.js";

class PreviewRequest {
  constructor(url) {
    this.url = url;
  }
}

class PreviewEndpoint {
  constructor(service = new PreviewService()) {
    this.service = service;
  }

  async import(request) {
    return this.service.load(request.url);
  }
}

export async function importPreview(url) {
  return new PreviewEndpoint().import(new PreviewRequest(url));
}
