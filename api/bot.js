export default async function handler(req, res) {
  // Vérifie si la requête vient bien de Telegram
  if (req.method === 'POST') {
    const update = req.body;
    
    // Vous placerez ici la logique de votre Agent Hermes / LLM
    console.log("Message reçu de Telegram :", update);

    return res.status(200.json({ status: 'ok' });
  }

  return res.status(200).send('Bot Hermes est en ligne sur Vercel !');
}
