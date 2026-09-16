function setupVoiceInput() {
  const button = document.getElementById('voice-input');
  const status = document.getElementById('voice-status');
  const Recognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!Recognition) {
    button.disabled = true;
    status.textContent = 'Voice input is unavailable in this browser.';
    return;
  }
  const recognition = new Recognition();
  recognition.continuous = false;
  recognition.interimResults = true;
  recognition.lang = navigator.language || 'en-US';
  let listening = false;
  recognition.onstart = () => {
    listening = true;
    button.textContent = 'Listening…';
    status.textContent = 'Speak your intent, then pause.';
  };
  recognition.onresult = event => {
    const transcript = Array.from(event.results).map(result => result[0].transcript).join('');
    if (transcript.trim()) document.getElementById('objective').value = transcript.trim();
  };
  recognition.onerror = event => { status.textContent = `Voice input failed: ${event.error}`; };
  recognition.onend = () => {
    listening = false;
    button.textContent = 'Speak';
    if (!status.textContent.startsWith('Voice input failed')) status.textContent = 'Voice input ready.';
  };
  button.addEventListener('click', () => {
    try {
      if (listening) recognition.stop();
      else recognition.start();
    } catch (error) {
      status.textContent = `Voice input failed: ${error.message}`;
    }
  });
  status.textContent = 'Voice input ready.';
}

window.CicadaVoice = {setup: setupVoiceInput};
