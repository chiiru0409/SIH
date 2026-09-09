import { ThreatIoc } from '../types/intelligence';

export const mockIntelligence: ThreatIoc[] = [
  {
    id: 'IOC-001',
    type: 'IP',
    value: '185.220.101.42',
    defangedValue: '185.220.101[.]42',
    status: 'KNOWN_MALICIOUS',
    threatCategory: 'Tor Exit / Bulletproof Proxy Node',
    riskScore: 94,
    firstSeen: '2026-08-12T10:00:00Z',
    lastSeen: '2026-09-09T08:42:15Z',
    detectionEngines: [
      { engineName: 'VirusTotal', verdict: '23/88 Security Vendors Flagged Malicious' },
      { engineName: 'AbuseIPDB', verdict: '100% Abuse Confidence Score (2,410 reports)' },
      { engineName: 'Spamhaus', verdict: 'Listed on SBL / CSS Drop list' },
      { engineName: 'Cisco Talos', verdict: 'Reputation: Poor / Blacklisted' }
    ],
    asnDetails: {
      asn: 'AS49505',
      org: 'HostRoyale Ltd (Bulletproof Provider)',
      country: 'NL',
      cidr: '185.220.101.0/24'
    },
    geoDetails: {
      country: 'Netherlands',
      city: 'Amsterdam',
      latitude: 52.3702,
      longitude: 4.8952
    },
    associatedCases: ['CASE-2026-0842', 'CASE-2026-0845'],
    associatedCampaigns: ['CAMPAIGN-0042']
  },
  {
    id: 'IOC-002',
    type: 'DOMAIN',
    value: 'micros0ft-security-auth.com',
    defangedValue: 'micros0ft-security-auth[.]com',
    status: 'KNOWN_MALICIOUS',
    threatCategory: 'Typosquatting / Credential Harvesting',
    riskScore: 98,
    firstSeen: '2026-09-08T06:00:00Z',
    lastSeen: '2026-09-09T08:42:15Z',
    detectionEngines: [
      { engineName: 'Google Safe Browsing', verdict: 'Phishing Landing Site' },
      { engineName: 'URLhaus', verdict: 'Active Phishing Database match' },
      { engineName: 'PhishTank', verdict: 'Verified Phishing Site #849102' }
    ],
    whois: {
      registrar: 'NameCheap, Inc. (Privacy Protected)',
      creationDate: '2026-09-08T05:32:00Z (1 day ago)',
      expirationDate: '2027-09-08T05:32:00Z',
      registrantOrg: 'Withheld for Privacy Purpose',
      registrantCountry: 'IS'
    },
    associatedCases: ['CASE-2026-0842'],
    associatedCampaigns: ['CAMPAIGN-0042']
  },
  {
    id: 'IOC-003',
    type: 'URL',
    value: 'https://login.micros0ft-security-auth.com/adfs/ls/?client_id=msft-auth-token-9941',
    defangedValue: 'hxxps://login[.]micros0ft-security-auth[.]com/adfs/ls/?client_id=msft-auth-token-9941',
    status: 'KNOWN_MALICIOUS',
    threatCategory: 'Live Phishing Harvester Endpoint',
    riskScore: 99,
    firstSeen: '2026-09-08T07:15:00Z',
    lastSeen: '2026-09-09T08:42:15Z',
    detectionEngines: [
      { engineName: 'Microsoft Defender SmartScreen', verdict: 'Blocked: Phishing' },
      { engineName: 'OpenPhish', verdict: 'Brand: Microsoft ADFS' }
    ],
    associatedCases: ['CASE-2026-0842'],
    associatedCampaigns: ['CAMPAIGN-0042']
  },
  {
    id: 'IOC-004',
    type: 'IP',
    value: '45.154.255.89',
    defangedValue: '45.154.255[.]89',
    status: 'SUSPICIOUS',
    threatCategory: 'High Risk VPS / Offshore Relay',
    riskScore: 78,
    firstSeen: '2026-09-01T14:00:00Z',
    lastSeen: '2026-09-09T09:15:30Z',
    detectionEngines: [
      { engineName: 'AbuseIPDB', verdict: '72% Suspicious Confidence Score' },
      { engineName: 'GreyNoise', verdict: 'Mass Scanner / Uncategorized' }
    ],
    asnDetails: {
      asn: 'AS200000',
      org: 'PonyNet Global Offshore Hosting',
      country: 'RU',
      cidr: '45.154.255.0/24'
    },
    geoDetails: {
      country: 'Russia',
      city: 'Moscow',
      latitude: 55.7558,
      longitude: 37.6173
    },
    associatedCases: ['CASE-2026-0843'],
    associatedCampaigns: ['CAMPAIGN-0038']
  },
  {
    id: 'IOC-005',
    type: 'FILE_HASH_SHA256',
    value: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    defangedValue: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    status: 'KNOWN_MALICIOUS',
    threatCategory: 'AgentTesla Infostealer PDF Dropper',
    riskScore: 98,
    firstSeen: '2026-09-05T04:10:00Z',
    lastSeen: '2026-09-09T06:12:00Z',
    detectionEngines: [
      { engineName: 'VirusTotal', verdict: '61/72 Vendors Flagged Trojan:Script/AgentTesla' },
      { engineName: 'Hybrid Analysis', verdict: 'Threat Score: 100/100 (Malicious Macro)' },
      { engineName: 'ANY.RUN', verdict: 'C2 HTTP Callback detected to 103.145.13.77:587' }
    ],
    associatedCases: ['CASE-2026-0844'],
    associatedCampaigns: ['CAMPAIGN-0029']
  },
  {
    id: 'IOC-006',
    type: 'IP',
    value: '198.51.100.24',
    defangedValue: '198.51.100[.]24',
    status: 'BENIGN',
    threatCategory: 'Corporate Internal Gateway',
    riskScore: 4,
    firstSeen: '2024-01-01T00:00:00Z',
    lastSeen: '2026-09-09T07:11:00Z',
    detectionEngines: [
      { engineName: 'Spamhaus', verdict: 'Clean / Certified Corporate IP' },
      { engineName: 'VirusTotal', verdict: '0/88 Flagged' }
    ],
    asnDetails: {
      asn: 'AS15169',
      org: 'Enterprise Internal Infrastructure Ltd',
      country: 'US',
      cidr: '198.51.100.0/24'
    },
    geoDetails: {
      country: 'United States',
      city: 'Ashburn',
      latitude: 39.0438,
      longitude: -77.4874
    },
    associatedCases: ['CASE-2026-0775'],
    associatedCampaigns: []
  }
];
