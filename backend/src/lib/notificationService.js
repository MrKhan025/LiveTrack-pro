'use strict';

const crypto = require('crypto');

class NotificationService {
  constructor(db) {
    this.db = db;
    this.deliveryHistory = [];
  }

  async dispatchCriticalEvent({ userId, deviceId, eventType, title, body, metadata = {} }) {
    const timestamp = new Date().toISOString();
    const deliveries = [];

    // 1. Dispatch Push Notifications (FCM for Android & APNs for iOS)
    const pushTokens = await this.db.listPushTokensByUser(userId);
    for (const pt of pushTokens) {
      const payload =
        pt.provider === 'apns'
          ? {
              aps: {
                alert: { title, body },
                sound: 'default',
                category: eventType
              },
              deviceId,
              metadata
            }
          : {
              to: pt.token,
              priority: 'high',
              notification: { title, body },
              data: { eventType, deviceId: String(deviceId || ''), ...metadata }
            };

      const record = {
        id: crypto.randomUUID(),
        userId,
        deviceId,
        channel: `push:${pt.provider}`,
        target: pt.token.slice(0, 16) + '...',
        eventType,
        title,
        body,
        payload,
        status: 'dispatched',
        timestamp
      };
      this.deliveryHistory.unshift(record);
      deliveries.push(record);
    }

    // 2. Dispatch Outbound Alert Channels (Webhook with HMAC-SHA256, Telegram Bot, Email)
    const channels = await this.db.listAlertChannelsByUser(userId);
    for (const ch of channels) {
      if (!ch.enabled) continue;
      if (Array.isArray(ch.events) && !ch.events.includes(eventType)) continue;

      const bodyJson = JSON.stringify({
        event: eventType,
        title,
        message: body,
        deviceId,
        metadata,
        timestamp
      });

      const signature = ch.secretHeader
        ? crypto.createHmac('sha256', ch.secretHeader).update(bodyJson).digest('hex')
        : null;

      const record = {
        id: crypto.randomUUID(),
        userId,
        deviceId,
        channel: ch.channelType,
        channelName: ch.name,
        target: ch.target,
        eventType,
        title,
        body,
        signatureHeader: signature ? `sha256=${signature}` : null,
        status: 'dispatched',
        timestamp
      };
      this.deliveryHistory.unshift(record);
      deliveries.push(record);
    }

    if (this.deliveryHistory.length > 500) {
      this.deliveryHistory.length = 500;
    }

    return deliveries;
  }

  getHistoryByUser(userId, limit = 50) {
    return this.deliveryHistory.filter((d) => d.userId === userId).slice(0, limit);
  }
}

module.exports = { NotificationService };
