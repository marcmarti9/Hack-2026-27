let vigiaHelpId = 0;

function ayudaHTML(tema, texto) {
  const id = `vigia-ayuda-${++vigiaHelpId}`;
  return `<span class="vigia-help">
    <button type="button" class="vigia-help-button" aria-label="Ayuda sobre ${esc(tema)}" aria-describedby="${id}">?</button>
    <span id="${id}" class="vigia-help-tip" role="tooltip" popover="manual">${esc(texto)}</span>
  </span>`;
}

{
  let pending;
  const openTip = () => document.querySelector('.vigia-help-tip:popover-open');

  function position(tip) {
    const anchor = tip.previousElementSibling.getBoundingClientRect();
    const {width, height} = tip.getBoundingClientRect();
    const center = anchor.left + anchor.width / 2;
    const left = Math.min(Math.max(8, center - width / 2), document.documentElement.clientWidth - width - 8);
    const above = anchor.bottom + height + 16 > window.innerHeight && anchor.top >= height + 16;
    tip.dataset.side = above ? 'above' : 'below';
    tip.style.left = `${left}px`;
    tip.style.top = `${above ? anchor.top - height - 8 : anchor.bottom + 8}px`;
    tip.style.setProperty('--help-arrow', `${center - left}px`);
  }

  function show(help) {
    clearTimeout(pending);
    const tip = help.querySelector('[popover]');
    const current = openTip();
    if (tip === current) return tip;
    current?.hidePopover();
    tip.dataset.pinned = 'false';
    tip.showPopover();
    position(tip);
    return tip;
  }

  function scheduleHide(help) {
    const tip = openTip();
    if (tip?.parentElement !== help || tip.dataset.pinned === 'true') return;
    clearTimeout(pending);
    pending = setTimeout(() => {
      if (!help.matches(':hover, :focus-within') && tip === openTip()) tip.hidePopover();
    }, 160);
  }

  document.addEventListener('pointerover', event => {
    const help = event.target.closest('.vigia-help');
    if (help && event.pointerType !== 'touch') show(help);
  });
  document.addEventListener('pointerout', event => {
    const help = event.target.closest('.vigia-help');
    if (help && !help.contains(event.relatedTarget)) scheduleHide(help);
  });
  document.addEventListener('focusin', event => {
    const button = event.target.closest('.vigia-help-button');
    if (button) show(button.parentElement);
  });
  document.addEventListener('focusout', event => {
    const button = event.target.closest('.vigia-help-button');
    if (button) scheduleHide(button.parentElement);
  });
  document.addEventListener('click', event => {
    const button = event.target.closest('.vigia-help-button');
    if (!button) {
      const current = openTip();
      if (current && !current.contains(event.target)) current.hidePopover();
      return;
    }
    const tip = show(button.parentElement);
    if (tip.dataset.pinned === 'true') tip.hidePopover();
    else tip.dataset.pinned = 'true';
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') openTip()?.hidePopover();
  });
  function reposition() {
    const tip = openTip();
    if (tip) position(tip);
  }
  window.addEventListener('scroll', reposition, true);
  window.addEventListener('resize', reposition);
}
