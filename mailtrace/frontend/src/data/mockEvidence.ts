import { CryptographicEvidence } from '../types/evidence';

export const mockEvidence: Record<string, CryptographicEvidence> = {
  'CASE-2026-0842': {
    caseId: 'CASE-2026-0842',
    emailId: 'EML-2026-0842',
    rawEmailSha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
    parsedMetadataSha256: 'b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef1',
    analysisArtifactSha256: 'c3d4e5f6a1b27890123456789abcdef0123456789abcdef0123456789abcdef2',
    merkleRootHash: 'd4e5f6a1b2c37890123456789abcdef0123456789abcdef0123456789abcdef3',
    timestamp: '2026-09-09T08:42:15Z',
    isTamperEvident: true,
    tamperStatus: 'VERIFIED_VALID',
    blockchainAnchor: {
      network: 'SIH-IMMUTABLE-LEDGER (SIMULATED)',
      blockNumber: 4892011,
      transactionHash: '0x94f1c8e03bd516f4439c25f46a2a0ebaa297df0c3451cbfca96a84c89eb25139',
      merkleRoot: 'd4e5f6a1b2c37890123456789abcdef0123456789abcdef0123456789abcdef3',
      anchoredAt: '2026-09-09T08:42:18Z',
      verified: true
    },
    auditTrail: [
      {
        step: 1,
        action: 'Ingestion & Raw RFC-822 SHA-256 Checksum Calculation',
        actor: 'MailTrace Ingestion Gateway v2.4',
        timestamp: '2026-09-09T08:42:15.102Z',
        hashBefore: 'GENESIS',
        hashAfter: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
        status: 'VALID'
      },
      {
        step: 2,
        action: 'Forensic Header & MIME Structural Deconstruction',
        actor: 'Parser Engine Worker #04',
        timestamp: '2026-09-09T08:42:15.340Z',
        hashBefore: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
        hashAfter: 'b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef1',
        status: 'VALID'
      },
      {
        step: 3,
        action: 'AI Threat Scoring & Multi-Layer Feature Extraction',
        actor: 'Threat Intelligence Engine v3.1',
        timestamp: '2026-09-09T08:42:15.890Z',
        hashBefore: 'b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef1',
        hashAfter: 'c3d4e5f6a1b27890123456789abcdef0123456789abcdef0123456789abcdef2',
        status: 'VALID'
      },
      {
        step: 4,
        action: 'Merkle Leaf Inclusion & Blockchain Anchor Commit',
        actor: 'Evidence Integrity Manager',
        timestamp: '2026-09-09T08:42:18.012Z',
        hashBefore: 'c3d4e5f6a1b27890123456789abcdef0123456789abcdef0123456789abcdef2',
        hashAfter: 'd4e5f6a1b2c37890123456789abcdef0123456789abcdef0123456789abcdef3',
        status: 'VALID'
      }
    ]
  },
  'CASE-2026-0843': {
    caseId: 'CASE-2026-0843',
    emailId: 'EML-2026-0843',
    rawEmailSha256: 'e5f6a1b2c3d47890123456789abcdef0123456789abcdef0123456789abcdef4',
    parsedMetadataSha256: 'f6a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef5',
    analysisArtifactSha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef6',
    merkleRootHash: 'b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef7',
    timestamp: '2026-09-09T09:15:30Z',
    isTamperEvident: true,
    tamperStatus: 'VERIFIED_VALID',
    blockchainAnchor: {
      network: 'SIH-IMMUTABLE-LEDGER (SIMULATED)',
      blockNumber: 4892044,
      transactionHash: '0x12a83efb980a3c94f2748102837bcdef49102847193820194857291039485710',
      merkleRoot: 'b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef7',
      anchoredAt: '2026-09-09T09:15:34Z',
      verified: true
    },
    auditTrail: [
      {
        step: 1,
        action: 'Ingestion & Raw RFC-822 SHA-256 Checksum Calculation',
        actor: 'MailTrace Ingestion Gateway v2.4',
        timestamp: '2026-09-09T09:15:30.210Z',
        hashBefore: 'GENESIS',
        hashAfter: 'e5f6a1b2c3d47890123456789abcdef0123456789abcdef0123456789abcdef4',
        status: 'VALID'
      },
      {
        step: 2,
        action: 'BEC Financial Entity Recognition & Impersonation Analysis',
        actor: 'Identity Intelligence Worker #02',
        timestamp: '2026-09-09T09:15:30.880Z',
        hashBefore: 'e5f6a1b2c3d47890123456789abcdef0123456789abcdef0123456789abcdef4',
        hashAfter: 'f6a1b2c3d4e57890123456789abcdef0123456789abcdef0123456789abcdef5',
        status: 'VALID'
      }
    ]
  }
};
