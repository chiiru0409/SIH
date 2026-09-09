export type IocType = 'IP' | 'DOMAIN' | 'URL' | 'FILE_HASH_SHA256' | 'SENDER_EMAIL' | 'ASN';
export type IntelStatus = 'KNOWN_MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN' | 'UNAVAILABLE';

export interface ThreatIoc {
  id: string;
  type: IocType;
  value: string;
  defangedValue: string;
  status: IntelStatus;
  threatCategory: string;
  riskScore: number;
  firstSeen: string;
  lastSeen: string;
  detectionEngines: {
    engineName: string;
    verdict: string;
  }[];
  whois?: {
    registrar: string;
    creationDate: string;
    expirationDate: string;
    registrantOrg: string;
    registrantCountry: string;
  };
  asnDetails?: {
    asn: string;
    org: string;
    country: string;
    cidr: string;
  };
  geoDetails?: {
    country: string;
    city: string;
    latitude: number;
    longitude: number;
  };
  associatedCases: string[];
  associatedCampaigns: string[];
}
