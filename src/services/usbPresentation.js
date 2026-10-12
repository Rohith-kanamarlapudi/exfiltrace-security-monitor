// Display projection only. API provenance, canonical hashes and stored evidence
// remain untouched; the header dropdown exposes the simulation context.
export function forensicsPresentation(value) {
  if (Array.isArray(value)) return value.map(forensicsPresentation)
  if (!value || typeof value !== 'object') return value
  const result = Object.fromEntries(Object.entries(value).map(([key, item]) => [key, forensicsPresentation(item)]))
  const overlayInterface = value.simulated === true && Array.isArray(value.functions)
    || value.hardwareIds?.some((id) => id.startsWith('EXFILTRACE_SIMULATION\\'))
  if (overlayInterface) {
    if ('name' in result) result.name = 'Keyboard / HID interface'
    if ('instanceId' in result) result.instanceId = null
    result.hardwareIds = []
    result.compatibleIds = []
    delete result.simulated
  }
  return result
}

export function connectedUsbPresentation(devices = [], context) {
  return devices.map((device) => {
    const observation = context?.observation?.actualDeviceId === device.deviceId ? context.observation : device
    return { ...forensicsPresentation(observation), id: device.id,
      hasInterfaceFinding: !!context?.alert && context.alert.device?.deviceId === device.deviceId }
  })
}
