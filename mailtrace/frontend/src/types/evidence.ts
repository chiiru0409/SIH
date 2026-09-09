export interface CryptographicEvidence {
  caseId: string;
  emailId: string;
  rawEmailSha256: string;
  parsedMetadataSha256: string;
  analysisArtifactSha256: string;
  merkleRootHash: string;
  timestamp: string;
  isTamperEvident: boolean;
  tamperStatus: 'VERIFIED_VALID' | 'TAMPER_DETECTED' | 'UNVERIFIED';
  blockchainAnchor: {
    network: 'SIH-IMMUTABLE-LEDGER (SIMULATED)';
    blockNumber: number;
    transactionHash: string;
    merkleRoot: string;
    anchoredAt: string;
    verified: boolean;
  };
  auditTrail: {
    step: number;
    action: string;
    actor: string;
    timestamp: string;
    hashBefore: string;
    hashAfter: string;
    status: 'VALID' | 'ANOMALOUS';
  }[];
}
