'use strict';

const byId = (id) => document.getElementById(id);
let csrf = '';

function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64Url(value) {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function prepareCreationOptions(options) {
  options.challenge = decodeBase64Url(options.challenge);
  options.user.id = decodeBase64Url(options.user.id);
  if (options.excludeCredentials) {
    options.excludeCredentials = options.excludeCredentials.map((item) => ({
      ...item,
      id: decodeBase64Url(item.id),
    }));
  }
  return options;
}

function serializeCredential(credential) {
  const result = {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {},
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  for (const key of ['clientDataJSON', 'attestationObject']) {
    if (credential.response[key]) {
      result.response[key] = encodeBase64Url(credential.response[key]);
    }
  }
  if (credential.response.getTransports) {
    result.response.transports = credential.response.getTransports();
  }
  if (credential.authenticatorAttachment) {
    result.authenticatorAttachment = credential.authenticatorAttachment;
  }
  return result;
}

async function postJson(path, body) {
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf,
    },
    body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || '登録に失敗しました');
  return result;
}

byId('register').addEventListener('click', async () => {
  const button = byId('register');
  const message = byId('message');
  button.disabled = true;
  message.textContent = '';
  try {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      throw new Error('このブラウザーはWebAuthn Passkeyに対応していません。');
    }
    const options = await postJson('/api/register/options', {
      bootstrap_token: byId('bootstrap-token').value,
    });
    csrf = options.csrf;
    const credential = await navigator.credentials.create({
      publicKey: prepareCreationOptions(options.options),
    });
    if (!credential) throw new Error('Passkey登録がキャンセルされました。');
    const result = await postJson('/api/register/verify', {
      csrf,
      credential: serializeCredential(credential),
    });
    byId('token-row').hidden = true;
    button.hidden = true;
    message.textContent = result.message;
  } catch (error) {
    message.textContent = error instanceof Error ? error.message : '登録に失敗しました。';
    button.disabled = false;
  }
});

if (!window.PublicKeyCredential || !navigator.credentials) {
  byId('register').disabled = true;
  byId('message').textContent = 'このブラウザーはWebAuthn Passkeyに対応していません。';
}
