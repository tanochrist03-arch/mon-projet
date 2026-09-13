export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(200).send('Agent Hermes IA est en ligne et à l écoute !');
  }

  try {
    const { message } = req.body;
    if (!message || !message.text) {
      return res.status(200).json({ status: 'no_message' });
    }

    const chatId = message.chat.id;
    const userText = message.text;
    const telegramToken = process.env.TELEGRAM_BOT_TOKEN || '8812176684:AAFQKagj3DBZCDJowCe7rac4zfD8tD8u4To';
    const geminiKey = process.env.GEMINI_API_KEY;

    let replyText = "";

    if (geminiKey) {
      // Appel direct à l'API Gemini
      const aiResponse = await fetch(https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=\, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{
            parts: [{ text: Tu es Agent Hermes, un assistant virtuel intelligent, utile et sympa. Réponds de manière naturelle et concise à ce message : \ }]
          }]
        })
      });

      const data = await aiResponse.json();
      if (data.candidates && data.candidates[0]?.content?.parts?.[0]?.text) {
        replyText = data.candidates[0].content.parts[0].text;
      } else {
        replyText = "J'ai eu un petit décrochage au niveau de mes circuits neuronaux. Peux-tu répéter ?";
      }
    } else {
      // Mode simulation en attendant la clé API
      replyText = Agent Hermes (Mode IA en attente de clé) : J'ai bien reçu "\".;
    }

    // Envoyer la réponse sur Telegram
    await fetch(https://api.telegram.org/bot\/sendMessage, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: replyText
      })
    });

    return res.status(200).json({ status: 'success' });
  } catch (error) {
    console.error('Erreur du bot :', error);
    return res.status(500).json({ error: error.message });
  }
}
