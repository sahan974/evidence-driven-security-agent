import { DocumentService } from "./document-service.js";

class DocumentRequest {
  constructor(name) {
    this.name = name;
  }
}

class DocumentEndpoint {
  constructor(service = new DocumentService()) {
    this.service = service;
  }

  async get(request) {
    return this.service.retrieve(request.name);
  }
}

export async function loadDocument(name) {
  return new DocumentEndpoint().get(new DocumentRequest(name));
}
