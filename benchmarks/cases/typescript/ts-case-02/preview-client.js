export async function fetchPreview(url) {
  const response = await fetch(url);
  return response.text();
}
