const clients = new Map();

function writeEvent(res, event, data) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

function addTopupClient(userId, res) {
  const key = String(userId);

  if (!clients.has(key)) {
    clients.set(key, new Set());
  }

  clients.get(key).add(res);
  writeEvent(res, 'connected', { userId, timestamp: new Date().toISOString() });

  return () => {
    const userClients = clients.get(key);
    if (!userClients) return;

    userClients.delete(res);
    if (userClients.size === 0) {
      clients.delete(key);
    }
  };
}

function emitTopupSuccess(payload) {
  const key = String(payload.userId);
  const userClients = clients.get(key);

  if (!userClients) return;

  userClients.forEach((res) => {
    writeEvent(res, 'topup_success', {
      ...payload,
      timestamp: new Date().toISOString()
    });
  });
}

function emitTransferSuccess({ senderId, receiverId, senderName, receiverName, amount, senderSaldoAfter, receiverSaldoAfter }) {
  const timestamp = new Date().toISOString();

  const senderClients = clients.get(String(senderId));
  if (senderClients) {
    senderClients.forEach(res => {
      writeEvent(res, 'transfer_sent', {
        receiverName, amount, saldoAfter: senderSaldoAfter, timestamp
      });
    });
  }

  const receiverClients = clients.get(String(receiverId));
  if (receiverClients) {
    receiverClients.forEach(res => {
      writeEvent(res, 'transfer_received', {
        senderName, amount, saldoAfter: receiverSaldoAfter, timestamp
      });
    });
  }
}

module.exports = { addTopupClient, emitTopupSuccess, emitTransferSuccess };
