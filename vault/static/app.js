// Dashboard without CDN or innerHTML: every untrusted value (node_id, note, reasons,
// manifest fields) is rendered with textContent so "<script>" shows up as text.
'use strict'

const $ = (id) => document.getElementById(id)
let current = null

function el(tag, text, className) {
  const node = document.createElement(tag)
  if (text !== undefined && text !== null) node.textContent = String(text)
  if (className) node.className = className
  return node
}

function badge(status) {
  return el('span', status, 'badge s-' + String(status).toLowerCase())
}

async function api(path, options) {
  const res = await fetch(path, options)
  if (!res.ok) throw new Error(res.status + ' ' + (await res.text()))
  return res.json()
}

async function loadBundles() {
  const bundles = await api('/api/bundles')
  const body = $('bundles')
  body.replaceChildren()
  for (const b of bundles) {
    const tr = el('tr')
    const statusCell = el('td')
    statusCell.append(badge(b.status))
    tr.append(statusCell, el('td', b.bundle_id || b.bundle_sha256.slice(0, 16)), el('td', b.node_id || '-'), el('td', b.key_id || '-'), el('td', b.received_at))
    tr.addEventListener('click', () => showDetail(b.bundle_sha256))
    body.append(tr)
  }
  const head = await api('/api/custody/head')
  $('head').textContent = head.head_entry_hash.slice(0, 20) + '... (' + head.count + ' entri)'
}

async function showDetail(sha) {
  const b = await api('/api/bundles/' + sha)
  current = sha
  $('detail').hidden = false
  $('d-title').textContent = b.bundle_id || 'Bundle tanpa manifest sah'
  $('d-status').replaceChildren(badge(b.status))
  $('d-sha').textContent = b.bundle_sha256
  $('d-reasons').replaceChildren(...b.reasons.map((r) => el('li', r)))
  const arts = (b.manifest && b.manifest.artifacts) || []
  $('d-artifacts').replaceChildren(
    ...arts.map((a) => {
      const tr = el('tr')
      tr.append(el('td', a.path), el('td', a.sha256.slice(0, 24) + '...'), el('td', a.size_bytes), el('td', a.redactions))
      return tr
    }),
  )
  const nodeEvents = ((b.manifest && b.manifest.custody_events) || []).map((e) => ({
    when: e.timestamp, what: e.action + ' (node, dilaporkan sendiri)', who: e.actor, detail: e.note,
  }))
  const vaultEvents = b.custody.map((e) => ({
    when: e.timestamp, what: e.action, who: e.actor, detail: e.detail + '  #' + e.entry_hash.slice(0, 10),
  }))
  $('d-custody').replaceChildren(
    ...nodeEvents.concat(vaultEvents).map((e) => el('li', e.when + '  ' + e.what + '  [' + e.who + ']  ' + (e.detail || ''))),
  )
}

$('reverify').addEventListener('click', async () => {
  if (!current) return
  try {
    await api('/api/bundles/' + current + '/reverify', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + $('token').value },
    })
    await showDetail(current)
    await loadBundles()
  } catch (err) {
    alert(err.message)
  }
})

$('check-chain').addEventListener('click', async () => {
  const r = await api('/api/custody/verify')
  $('chain-result').textContent = r.ok ? 'utuh (' + r.checked + ' entri)' : 'PUTUS di entri #' + r.broken_at
  $('chain-result').className = r.ok ? 'ok' : 'bad'
})

loadBundles()
setInterval(loadBundles, 3000)
