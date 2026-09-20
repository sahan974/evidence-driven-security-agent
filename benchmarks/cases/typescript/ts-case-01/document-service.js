import { DocumentStore } from "./document-store.js";

export class DocumentService {
  constructor(store = new DocumentStore()) {
    this.store = store;
  }

  async retrieve(requestedName) {
    const name = requestedName.trim();
    if (!name) throw new Error("a document name is required");
    return this.store.readText(name);
  }
}
