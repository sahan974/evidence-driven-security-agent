import { fetchPreview } from "./preview-client.js";

export class PreviewService {
  async load(rawUrl) {
    const url = new URL(rawUrl).toString();
    return fetchPreview(url);
  }
}
