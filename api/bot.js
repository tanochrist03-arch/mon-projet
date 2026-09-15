export default async function handler(req, res) {
  // On traite d'abord, puis on répond 200 — et on répond TOUJOURS 200 à Telegram
  // (sinon Telegram réessaie en boucle le même update).
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') {
    return res.status(200).json({ ok: true });
  }

  // Le token vit désormais dans les variables d'environnement Vercel.
  // Jamais en dur dans le code, jamais commité.
  const token = process.env.TELEGRAM_BOT_TOKEN;

  try {
    if (!token) {
      console.error('TELEGRAM_BOT_TOKEN manquant dans les variables d\'environnement.');
      return res.status(200).json({ ok: true });
    }

    let rawBody = '';

    // Lire le body en streaming
    for await (const chunk of req) {
      rawBody += chunk;
    }

    const update = JSON.parse(rawBody);

    if (update && update.message) {
      const chatId = update.message.chat.id;
      const text = update.message.text ? update.message.text.trim() : '';

      let replyText = "Bienvenue, Boss ! Agent Hermes est opérationnel sur Vercel.";
      if (text === '/services') replyText = "Module E-commerce actif.";
      if (text === '/opportunites') replyText = "Analyse des tendances en cours...";

      const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: chatId,
          text: replyText
        })
      });

      if (!response.ok) {
        const detail = await response.text();
        console.error('Echec sendMessage:', response.status, detail);
      }
    }

    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error('Erreur critique:', error);
    // On répond quand même 200 pour éviter les retries infinis de Telegram
    return res.status(200).json({ ok: true });
  }
}
