const BASE_URL = "http://localhost:8000/api/v1";

export async function analyzeRequest(data: any) {
  const response = await fetch(`${BASE_URL}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });

  return await response.json();
}

export async function getHistory() {
  const response = await fetch(`${BASE_URL}/history`);

  return await response.json();
}
