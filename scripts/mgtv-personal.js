// Personal, authorized playback credential configuration. Never log the ticket.
(function () {
  const url = typeof $request !== 'undefined' && $request && $request.url;
  const ticket = typeof $argument === 'object' && $argument && $argument.ticket;
  if (typeof url !== 'string' || !/^https:\/\/mobile-stream\.api\.mgtv\.com\/v1\/video\/source(?:\?|$)/.test(url) || typeof ticket !== 'string' || !/^[a-fA-F0-9]{32}$/.test(ticket) || url.includes('#')) return $done({});
  const count = (url.match(/[?&]ticket=/gi) || []).length;
  if (count > 1) return $done({});
  const result = count === 1 ? url.replace(/([?&]ticket=)[^&]*/i, (_, prefix) => prefix + ticket) : url + (url.includes('?') ? (/[?&]$/.test(url) ? '' : '&') : '?') + 'ticket=' + ticket;
  return $done({url: result});
})();
