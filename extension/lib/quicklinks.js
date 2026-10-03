// Popular research sites without a usable free API: offered as one-click searches.

export const QUICK_LINKS = [
  { id: 'talos', name: 'Cisco Talos', url: (ip) => `https://talosintelligence.com/reputation_center/lookup?search=${ip}` },
  { id: 'censys', name: 'Censys', url: (ip) => `https://platform.censys.io/hosts/${ip}` },
  { id: 'spur', name: 'Spur', url: (ip) => `https://spur.us/context/${ip}` },
  { id: 'xforce', name: 'IBM X-Force', url: (ip) => `https://exchange.xforce.ibmcloud.com/ip/${ip}` },
  { id: 'urlscan', name: 'urlscan.io', url: (ip) => `https://urlscan.io/ip/${ip}` },
  { id: 'criminalip', name: 'Criminal IP', url: (ip) => `https://www.criminalip.io/asset/report/${ip}` },
  { id: 'scamalytics', name: 'Scamalytics', url: (ip) => `https://scamalytics.com/ip/${ip}` },
  { id: 'hebgp', name: 'HE BGP Toolkit', url: (ip) => `https://bgp.he.net/ip/${ip}` },
];
