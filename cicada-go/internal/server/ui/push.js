let pushSetup = false;

function decodeBase64URL(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

async function setupPush(api) {
  const button = document.getElementById('push-enable');
  const status = document.getElementById('push-status');
  if (!button || !status || pushSetup) return;
  if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) return;
  let config;
  try { config = await api('/v1/notifications/push/config'); }
  catch { return; }
  if (!config.enabled || !config.public_key) return;
  pushSetup = true;
  button.hidden = false;
  if (Notification.permission === 'denied') {
    status.textContent = 'Push permission is blocked in this browser.';
    button.disabled = true;
    return;
  }
  const registration = await navigator.serviceWorker.ready;
  const existing = await registration.pushManager.getSubscription();
  if (existing) {
    status.textContent = 'Push notifications are enabled.';
  }
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') throw new Error('Push permission was not granted.');
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: decodeBase64URL(config.public_key),
      });
      await api('/v1/notifications/push/subscriptions', {
        method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({...subscription.toJSON(), user_agent: navigator.userAgent}),
      });
      status.textContent = 'Push notifications are enabled.';
    } catch (error) {
      status.textContent = error.message || 'Push setup failed.';
      button.disabled = false;
    }
  });
}

window.CicadaPush = {setup: setupPush};
