export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const { url } = req.body;
  const API_KEY = process.env.VT_API_KEY;

  try {
    // Submit URL for scanning
    const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent(url)}`,
    });

    const submitData = await submitRes.json();
    const analysisId = submitData.data?.id;

    if (!analysisId) return res.status(400).json({ error: "Failed to submit URL" });

    // Wait and get results
    await new Promise(r => setTimeout(r, 3000));

    const resultRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { "x-apikey": API_KEY },
    });

    const resultData = await resultRes.json();
    const stats = resultData.data?.attributes?.stats;

    res.status(200).json({ stats, analysisId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}