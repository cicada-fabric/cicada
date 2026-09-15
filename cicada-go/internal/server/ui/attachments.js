function readFileAsDataURL(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error(`Could not read ${file.name}`));
    reader.readAsDataURL(file);
  });
}

async function uploadClientAttachments(api) {
  const files = [...document.getElementById('attachments').files];
  const link = document.getElementById('reference-link').value.trim();
  if (files.length > 5) throw new Error('Choose at most five attachments.');
  const uploaded = [];
  for (const file of files) {
    if (file.size > 8 * 1024 * 1024) throw new Error(`${file.name} exceeds 8 MB.`);
    const dataURL = await readFileAsDataURL(file);
    const attachment = await api('/v1/attachments', {
      method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({name: file.name, mime_type: file.type, content_base64: dataURL.split(',', 2)[1] || ''}),
    });
    uploaded.push(attachment.id);
  }
  if (link) {
    const attachment = await api('/v1/attachments', {
      method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({name: 'reference link', source_url: link}),
    });
    uploaded.push(attachment.id);
  }
  return uploaded;
}

window.CicadaAttachments = {upload: uploadClientAttachments};
