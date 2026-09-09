import { CampaignCluster } from '../types/campaign';

export const mockCampaigns: CampaignCluster[] = [
  {
    id: 'CAMPAIGN-0042',
    name: 'O365-CRED-HARVEST-BLITZ',
    theme: 'Microsoft 365 Password Expiration & MFA Reset Fraud',
    threatCategory: 'CREDENTIAL_HARVESTING',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    confidenceScore: 96,
    status: 'ACTIVE',
    firstObserved: '2026-09-08T06:14:00Z',
    lastObserved: '2026-09-09T08:42:15Z',
    totalEmails: 142,
    targetedRecipients: 89,
    targetedDepartments: ['Executive Leadership', 'Finance', 'Engineering', 'Human Resources'],
    sharedInfrastructure: {
      domains: ['micros0ft-security-auth[.]com', 'login-ms-auth-sso[.]net', 'aad-office365-verify[.]org'],
      ips: ['185.220.101.42', '194.26.29.110'],
      asns: ['AS49505 (HostRoyale Ltd)', 'AS62005 (Biterika LLC)'],
      urls: [
        'hxxps://login[.]micros0ft-security-auth[.]com/adfs/ls/?client_id=msft-auth-token-9941',
        'hxxps://login-ms-auth-sso[.]net/oauth2/authorize'
      ],
      attachmentHashes: []
    },
    correlationReasons: [
      {
        factor: 'Shared Reverse Proxy IP',
        description: 'Originating intermediate hop IP 185.220.101.42 detected across 47 emails targeting 12 distinct tenant mailboxes.',
        weight: 35
      },
      {
        factor: 'Punycode & Typosquat Template',
        description: 'Uniform landing page cloned from ADFS login template with identical base64 asset bundles.',
        weight: 30
      },
      {
        factor: 'Temporal Burst Pattern',
        description: 'Coordinated delivery waves triggered at 08:30 UTC specifically timed with APAC/EMEA morning work shifts.',
        weight: 20
      },
      {
        factor: 'DKIM Domain Mismatch',
        description: 'All samples spoof @microsoft.com in Header-From while DKIM signature d= is forged under disposable bulletproof domains.',
        weight: 15
      }
    ],
    timeline: [
      {
        timestamp: '2026-09-08T06:14:00Z',
        event: 'Initial reconnaissance probe targeting 5 HR inboxes',
        target: 'hr-dept@enterprise.com',
        associatedCaseId: 'CASE-2026-0801'
      },
      {
        timestamp: '2026-09-08T14:22:00Z',
        event: 'Domain pivot to secondary landing server login-ms-auth-sso[.]net',
        target: 'engineering-leads@enterprise.com',
        associatedCaseId: 'CASE-2026-0819'
      },
      {
        timestamp: '2026-09-09T08:42:15Z',
        event: 'High-severity credential lure delivered to Chief Financial Officer',
        target: 'cfo@enterprise.com',
        associatedCaseId: 'CASE-2026-0842'
      }
    ],
    associatedCaseIds: ['CASE-2026-0842', 'CASE-2026-0845', 'CASE-2026-0801', 'CASE-2026-0819']
  },
  {
    id: 'CAMPAIGN-0038',
    name: 'FIN-WIRE-VIP-SPOOF',
    theme: 'Urgent M&A Wire Transfer & Escrow Impersonation',
    threatCategory: 'BEC',
    severity: 'HIGH',
    confidence: 'HIGH',
    confidenceScore: 91,
    status: 'ACTIVE',
    firstObserved: '2026-09-07T11:00:00Z',
    lastObserved: '2026-09-09T09:15:30Z',
    totalEmails: 18,
    targetedRecipients: 6,
    targetedDepartments: ['Finance', 'Accounts Payable', 'Treasury'],
    sharedInfrastructure: {
      domains: ['enterprise-holding-partners[.]co', 'corp-advisory-settlement[.]com'],
      ips: ['45.154.255.89', '91.240.118.204'],
      asns: ['AS200000 (PonyNet Global)', 'AS44050 (Stark Industries Hosting)'],
      urls: [],
      attachmentHashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
    },
    correlationReasons: [
      {
        factor: 'Display Name Impersonation Pattern',
        description: 'Targets C-suite executive display names (CEO / Board Chairman) with newly registered lookalike domains.',
        weight: 40
      },
      {
        factor: 'Bank Beneficiary Identifier Matching',
        description: 'Invoices request wire settlement routing to matching offshore intermediary accounts.',
        weight: 35
      },
      {
        factor: 'Linguistic Coercion Tone',
        description: 'NLP model flagged 99% match for non-disclosure urgency and out-of-band communication bypass requests.',
        weight: 25
      }
    ],
    timeline: [
      {
        timestamp: '2026-09-07T11:00:00Z',
        event: 'First lookalike domain registered via PrivacyGuard proxy',
        target: 'Domain Registry',
        associatedCaseId: 'CASE-2026-0790'
      },
      {
        timestamp: '2026-09-09T09:15:30Z',
        event: 'Urgent wire request sent to AP Lead demanding $485,000 transfer',
        target: 'ap-lead@enterprise.com',
        associatedCaseId: 'CASE-2026-0843'
      }
    ],
    associatedCaseIds: ['CASE-2026-0843', 'CASE-2026-0790']
  },
  {
    id: 'CAMPAIGN-0029',
    name: 'PDF-STEALER-LOGISTICS',
    theme: 'DHL / FedEx Shipping Clearance Malicious PDF Attachments',
    threatCategory: 'SUSPICIOUS',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    confidenceScore: 94,
    status: 'CONTAINED',
    firstObserved: '2026-09-05T04:10:00Z',
    lastObserved: '2026-09-08T17:20:00Z',
    totalEmails: 84,
    targetedRecipients: 45,
    targetedDepartments: ['Procurement', 'Supply Chain', 'Operations'],
    sharedInfrastructure: {
      domains: ['dhl-express-customs-clearance[.]com', 'fedex-intl-tracking-docs[.]net'],
      ips: ['103.145.13.77', '185.176.27.12'],
      asns: ['AS139220 (CloudHost Asia)', 'AS48693 (Velia.net)'],
      urls: ['hxxp://dhl-express-customs-clearance[.]com/payload/AgentTesla.bin'],
      attachmentHashes: [
        '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
      ]
    },
    correlationReasons: [
      {
        factor: 'AgentTesla Hash Signature',
        description: 'SHA-256 binary match for AgentTesla spyware dropper embedded in obfuscated JavaScript macro within PDF.',
        weight: 50
      },
      {
        factor: 'C2 Command Server Beaconing',
        description: 'SMTP beaconing to Russian hosting IP 103.145.13.77 over port 587.',
        weight: 35
      }
    ],
    timeline: [
      {
        timestamp: '2026-09-05T04:10:00Z',
        event: 'Initial surge detected against Supply Chain inboxes',
        target: 'logistics@enterprise.com',
        associatedCaseId: 'CASE-2026-0740'
      },
      {
        timestamp: '2026-09-08T17:20:00Z',
        event: 'Automated tenant quarantine applied to all matching hashes',
        target: 'All Tenant Inboxes',
        associatedCaseId: 'CASE-2026-0741'
      }
    ],
    associatedCaseIds: ['CASE-2026-0844', 'CASE-2026-0740', 'CASE-2026-0741']
  }
];
