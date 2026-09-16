module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(200).json({ status: 'Bot is running' });
  }

  const { message } = req.body;
  if (!message || !message.text) {
    return res.status(200).json({ ok: true });
  }

  const chatId = message.chat.id;
  const userText = message.text.trim();

  let replyText = "Désolé, une erreur est survenue.";

  try {
    const deepseekResponse = await fetch('https://api.deepseek.com/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.DEEPSEEK_API_KEY}`
      },
      body: JSON.stringify({
        model: "deepseek-chat",
        messages: [
          { 
            role: "system", 
            content: "Tu es un agent expert, technique et direct. Tu réponds toujours en français avec un ton professionnel et percutant, sans phrases bateaux d'assistant." 
          },
          { role: "user", content: userText }
        ],
        stream: false
      })
    });

    const data = await deepseekResponse.json();
    
    if (data.choices && data.choices.length > 0) {
      replyText = data.choices[0].message.content;
    }

  } catch (error) {
    console.error('Erreur:', error);
  }

  const token = process.env.TELEGRAM_BOT_TOKEN;
  await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text: replyText })
  });

  return res.status(200).json({ ok: true });
};