const svgNS = 'http://www.w3.org/2000/svg';

export function html(tag, className = '', text = '') {
  const value = document.createElement(tag);
  if (className) value.className = className;
  if (text !== '') value.textContent = String(text);
  return value;
}

export function svg(tag, attrs = {}, text = '') {
  const value = document.createElementNS(svgNS, tag);
  for (const [key, item] of Object.entries(attrs)) value.setAttribute(key, String(item));
  if (text !== '') value.textContent = String(text);
  return value;
}

export function textField(labelText, value = '', type = 'text') {
  const wrap = html('div', 'field');
  const label = html('label', '', labelText);
  const input = html('input');
  input.type = type;
  input.value = value;
  wrap.append(label, input);
  return { wrap, input };
}

export function selectField(labelText, options, selected = '') {
  const wrap = html('div', 'field');
  const label = html('label', '', labelText);
  const select = html('select');
  for (const option of options) {
    const item = html('option', '', option.label);
    item.value = option.value;
    item.selected = option.value === selected;
    select.append(item);
  }
  wrap.append(label, select);
  return { wrap, select };
}

export function button(label, run, kind = 'btn') {
  const value = html('button', kind, label);
  value.type = 'button';
  value.addEventListener('click', run);
  return value;
}
