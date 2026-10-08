// This script and every local CAPTCHA image are served by this NoiseFence host.
const token = location.hash.slice(1);
history.replaceState(null, '', location.pathname);
const element = (id) => document.getElementById(id);
const status = element('status');
const button = element('confirm');
const refresh = element('refresh');
const answer = element('answer');
let provider = '', proof = '', challenge = null, busy = false, completed = false;

async function call(path, body) {
  const response = await fetch('/api/v1/sender-verification/' + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body), credentials: 'omit', referrerPolicy: 'no-referrer',
  });
  if (!response.ok) {
    throw Error(response.status === 429
      ? 'Too many attempts. Please wait a minute before trying again.'
      : provider === 'self_hosted'
        ? 'Verification could not be completed. Request a new image and try again, or contact the recipient if the link has expired.'
        : 'Verification could not be completed. Please retry or contact the recipient if the link has expired.');
  }
  return response.json();
}
function ready() {
  if (!busy && !completed && challenge && Date.now() >= challenge.expires * 1000) {
    status.textContent = 'This image has expired. Select New image to continue.';
  }
  button.disabled = busy || completed || (provider === 'self_hosted'
    ? !challenge || Date.now() >= challenge.expires * 1000 || answer.value.trim().length !== 6
    : !proof);
}
async function newImage() {
  if (busy || completed) return;
  busy = true; challenge = null; answer.value = ''; refresh.disabled = true; ready();
  element('challenge-image').removeAttribute('src');
  status.textContent = 'Preparing a new image…';
  try {
    const value = await call('challenge', { token });
    if (!value.image.startsWith('data:image/png;base64,')) throw Error('Invalid challenge image.');
    challenge = value;
    element('challenge-image').src = value.image;
    status.textContent = 'Enter the code, then select Request delivery.';
  } catch (error) { status.textContent = error.message; }
  finally { busy = false; refresh.disabled = false; ready(); }
}
answer.addEventListener('input', ready);
answer.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') { event.preventDefault(); button.click(); }
});
refresh.addEventListener('click', newImage);
button.addEventListener('click', async () => {
  ready();
  if (button.disabled) return;
  busy = true; refresh.disabled = true; ready();
  const captcha = provider === 'self_hosted'
    ? JSON.stringify({ id: challenge.id, answer: answer.value.trim() }) : proof;
  status.textContent = 'Verifying…';
  try {
    await call('confirm', { token, captcha });
    completed = true;
    status.textContent = 'Confirmed. Eligible messages will be released shortly. You may close this page.';
  } catch (error) {
    status.textContent = error.message;
    if (provider === 'self_hosted') { challenge = null; answer.value = ''; }
    else { proof = ''; window.turnstile?.reset(); }
  } finally { busy = false; refresh.disabled = completed; ready(); }
});
(async () => {
  if (!token) { status.textContent = 'Open the complete verification link from your invitation email.'; return; }
  try {
    const info = await call('info', { token });
    provider = info.provider;
    if (provider === 'self_hosted') {
      element('local').hidden = false;
      element('privacy').textContent = 'This CAPTCHA is generated and verified by this NoiseFence server. No third-party CAPTCHA service receives your data.';
      await newImage();
    } else if (provider === 'turnstile') {
      element('privacy').textContent = 'The CAPTCHA is provided by Cloudflare Turnstile. Your message content is not sent to Cloudflare.';
      const script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      script.onload = () => {
        window.turnstile.render('#captcha', {
          sitekey: info.site_key, action: 'sender_verification', cData: info.id,
          callback: (value) => { proof = value; ready(); },
          'expired-callback': () => { proof = ''; ready(); },
          'error-callback': () => { proof = ''; ready(); status.textContent = 'CAPTCHA unavailable. Please retry later.'; },
        });
        status.textContent = 'Complete the verification to continue.';
      };
      script.onerror = () => { status.textContent = 'CAPTCHA unavailable. Please retry later.'; };
      document.head.appendChild(script);
    } else { throw Error('Unknown verification provider. Contact the recipient.'); }
  } catch (error) { status.textContent = error.message; }
})();
