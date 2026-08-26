export async function importPreview(url) {
  const response = await fetch(url);
  return response.text();
}
