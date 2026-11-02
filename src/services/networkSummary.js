const riskRank = { LOW: 0, MEDIUM: 1, HIGH: 2 }

// Summarize recorded flow events, keeping senders and recipients separate.
export function summarizeNetworkEvents(events, direction) {
  const groups = new Map()
  for (const event of events) {
    if (event.direction !== direction) continue
    const ip = direction === 'INBOUND' ? event.sourceIp : event.destinationIp
    let group = groups.get(ip)
    if (!group) {
      group = { id: `${direction}:${ip}`, ip, bytes: 0, flows: 0, risk: 'LOW',
        firstSeen: event.timestamp, lastSeen: event.timestamp, hosts: new Set(), protocols: new Set() }
      groups.set(ip, group)
    }
    group.bytes += event.packetSizeBytes
    group.flows += 1
    if (riskRank[event.risk] > riskRank[group.risk]) group.risk = event.risk
    if (event.timestamp < group.firstSeen) group.firstSeen = event.timestamp
    if (event.timestamp > group.lastSeen) group.lastSeen = event.timestamp
    group.protocols.add(event.protocol)
    // destinationHost must never be presented as the sender's hostname.
    if (direction === 'OUTBOUND' && event.destinationHost && event.destinationHost !== ip) {
      group.hosts.add(event.destinationHost)
    }
  }
  return [...groups.values()].map((group) => ({ ...group,
    hosts: [...group.hosts].sort(), protocols: [...group.protocols].sort(),
  })).sort((a, b) => b.bytes - a.bytes || a.ip.localeCompare(b.ip))
}
