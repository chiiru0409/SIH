import { EmailRecord } from '../types/email';

const RAW_EMAILS: any[] = [
  {
    id: 'em-0842',
    caseId: 'CASE-2026-0842',
    timestamp: '2026-09-09T08:14:22Z',
    subject: 'URGENT: Microsoft 365 Password Expiration Alert - Action Required',
    senderName: 'Microsoft 365 Security Team',
    senderAddress: 'security-alert@auth-ms-portal-update.com',
    recipientAddress: 'arjun.sharma@cyberdefense-org.gov.in',
    previewText: 'Your Microsoft 365 password will expire in 2 hours. Keep your current password by verifying your credentials immediately.',
    bodyText: `Dear User,

Your Microsoft 365 enterprise password will expire in 2 hours.
Failure to verify your identity will result in permanent account suspension.

Please click the secure portal link below to keep your current password:
https://login.micros0ft-security-portal.com/auth/verify?id=948291

If you did not request this, contact your IT administrator immediately.

Microsoft Security Operations Center
Reference Ticket: MS-SOC-94820`,
    bodyHtml: `<div style="font-family:sans-serif; color:#333; line-height:1.5;">
      <h3 style="color:#0078d4;">Microsoft 365 Security Operations</h3>
      <p>Dear User,</p>
      <p>Your <strong>Microsoft 365 enterprise password</strong> is scheduled to expire in <strong>2 hours</strong>.</p>
      <div style="background:#fff3cd; padding:12px; border-left:4px solid #ffc107; margin:16px 0;">
        <strong>Warning:</strong> Failure to confirm authentication will lead to immediate inbox access termination.
      </div>
      <p>
        <a href="https://login.micros0ft-security-portal.com/auth/verify?id=948291" style="background:#0078d4; color:#fff; padding:10px 20px; text-decoration:none; border-radius:4px; display:inline-block;">
          Keep Current Password & Verify
        </a>
      </p>
      <p style="font-size:12px; color:#666;">Microsoft Trust & Safety Division &bull; Case ID: MS-94820</p>
    </div>`,
    rawHeaders: `Received: from mail-relay-02.vpn-exit.nl (mail-relay-02.vpn-exit.nl [185.220.101.42])
  by mx.cyberdefense-org.gov.in (Postfix) with ESMTPS id 4Kz8J912
  for <arjun.sharma@cyberdefense-org.gov.in>; Wed, 9 Sep 2026 08:14:22 +0000 (UTC)
Received: from unknown (HELO auth-ms-portal-update.com) (194.26.29.110)
  by mail-relay-02.vpn-exit.nl with SMTP; Wed, 9 Sep 2026 08:14:18 +0000
From: "Microsoft 365 Security Team" <security-alert@auth-ms-portal-update.com>
To: <arjun.sharma@cyberdefense-org.gov.in>
Reply-To: <credentials-catcher-sys@proton.me>
Subject: URGENT: Microsoft 365 Password Expiration Alert - Action Required
Date: Wed, 9 Sep 2026 08:14:10 +0000
Message-ID: <20260909081410.A7920@auth-ms-portal-update.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
X-Mailer: PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)
Authentication-Results: mx.cyberdefense-org.gov.in;
  spf=fail (sender IP is 185.220.101.42) smtp.mailfrom=auth-ms-portal-update.com;
  dkim=fail (bad signature) header.d=auth-ms-portal-update.com;
  dmarc=fail (p=reject dis=none) header.from=auth-ms-portal-update.com`,
    threatCategory: 'PHISHING',
    secondaryCategories: ['CREDENTIAL_HARVESTING', 'IMPERSONATION'],
    severity: 'CRITICAL',
    riskScore: 87,
    confidenceScore: 94,
    status: 'PENDING_REVIEW',
    isQuarantined: false,
    isBlocked: false,
    isDefanged: true,
    campaignId: 'CAMPAIGN-0042',
    headers: {
      from: 'security-alert@auth-ms-portal-update.com',
      fromDisplayName: 'Microsoft 365 Security Team',
      fromDomain: 'auth-ms-portal-update.com',
      to: 'arjun.sharma@cyberdefense-org.gov.in',
      toDisplayName: 'Arjun Sharma (IT Infra Lead)',
      replyTo: 'credentials-catcher-sys@proton.me',
      replyToDomain: 'proton.me',
      returnPath: 'bounce-collector@auth-ms-portal-update.com',
      returnPathDomain: 'auth-ms-portal-update.com',
      messageId: '<20260909081410.A7920@auth-ms-portal-update.com>',
      date: 'Wed, 9 Sep 2026 08:14:10 +0000',
      subject: 'URGENT: Microsoft 365 Password Expiration Alert - Action Required',
      spfHeader: 'fail (sender IP 185.220.101.42 not permitted)',
      dkimHeader: 'fail (signature verification failed: key mismatch)',
      dmarcHeader: 'fail (p=reject dis=none header.from mismatch)',
      receivedHops: [
        {
          hopNumber: 1,
          fromServer: 'attacker-endpoint.local',
          fromIp: '194.26.29.110',
          byServer: 'mail-relay-02.vpn-exit.nl',
          timestamp: '2026-09-09T08:14:18Z',
          delaySeconds: 8,
          tlsVersion: 'TLSv1.2 (Weak Cipher)',
          isSuspicious: true,
          suspiciousReason: 'Unauthenticated origin node in Russian Bulletproof Hosting subnet',
          country: 'Russia',
          city: 'Saint Petersburg',
          asn: 'AS44050',
          org: 'Petersburg Cloud Interconnect',
        },
        {
          hopNumber: 2,
          fromServer: 'mail-relay-02.vpn-exit.nl',
          fromIp: '185.220.101.42',
          byServer: 'mx.cyberdefense-org.gov.in',
          timestamp: '2026-09-09T08:14:22Z',
          delaySeconds: 4,
          tlsVersion: 'TLSv1.3',
          isSuspicious: true,
          suspiciousReason: 'Known Tor Exit Node / High-risk Commercial VPN Gateway',
          country: 'Netherlands',
          city: 'Amsterdam',
          asn: 'AS60729',
          org: 'Zwiebelfreunde Tor Relay Service',
        },
        {
          hopNumber: 3,
          fromServer: 'mx.cyberdefense-org.gov.in',
          fromIp: '10.0.4.12',
          byServer: 'internal-mailbox-gw.cyberdefense-org.gov.in',
          timestamp: '2026-09-09T08:14:23Z',
          delaySeconds: 1,
          tlsVersion: 'TLSv1.3',
          isSuspicious: false,
          country: 'India',
          city: 'New Delhi',
          asn: 'AS55836',
          org: 'National Informatics Centre Gateway',
        }
      ],
      originatingIp: '185.220.101.42',
      xMailer: 'PHPMailer 6.8.0',
      mimeVersion: '1.0',
      contentType: 'text/html; charset="UTF-8"',
      identityMismatch: true,
      identityMismatchDetails: 'Display name claims "Microsoft 365" but domain is newly-registered "auth-ms-portal-update.com" and reply-to points to "proton.me".'
    },
    auth: {
      spf: {
        status: 'FAIL',
        domain: 'auth-ms-portal-update.com',
        senderIp: '185.220.101.42',
        aligned: false,
        reason: 'Sender IP 185.220.101.42 is not authorized in SPF record for auth-ms-portal-update.com',
      },
      dkim: {
        status: 'FAIL',
        domain: 'auth-ms-portal-update.com',
        selector: 'default',
        aligned: false,
        reason: 'RSA signature verification failed against public key DNS record',
      },
      dmarc: {
        status: 'FAIL',
        policy: 'reject',
        disposition: 'quarantine',
        aligned: false,
        reason: 'Both SPF and DKIM failed alignment with Header From domain',
      }
    },
    urls: [
      {
        originalUrl: 'https://login.micros0ft-security-portal.com/auth/verify?id=948291',
        defangedUrl: 'hxxps://login[.]micros0ft-security-portal[.]com/auth/verify?id=948291',
        domain: 'login.micros0ft-security-portal.com',
        registrableDomain: 'micros0ft-security-portal.com',
        ip: '185.220.101.42',
        asn: 'AS60729',
        asnOrg: 'Zwiebelfreunde Tor Relay Service',
        country: 'Netherlands',
        isPunycode: false,
        hasSuspiciousKeyword: true,
        isShortener: false,
        isCredentialPath: true,
        reputationScore: 96,
        threatTags: ['Typosquatting: micros0ft (0 instead of o)', 'Credential Harvest Endpoint', 'Fresh Domain (<48h)']
      }
    ],
    attachments: [],
    tags: ['Brand Impersonation', 'O365 Lure', 'Urgency Cue', 'Tor Relay Infrastructure']
  },
  {
    id: 'em-0891',
    caseId: 'CASE-2026-0891',
    timestamp: '2026-09-09T07:42:10Z',
    subject: 'URGENT: Updated Bank Remittance Details - Q3 Vendor Settlement',
    senderName: 'Robert Chen (Chief Financial Officer)',
    senderAddress: 'rchen-cfo@exec-finance-corp.xyz',
    recipientAddress: 'sneha.patel@cyberdefense-org.gov.in',
    previewText: 'Sneha, please hold the pending wire transfer for Apex Infrastructure. Our treasury account routing details have changed for Q3 settlement.',
    bodyText: `Sneha,

Please hold the pending wire transfer for Apex Infrastructure. Our beneficiary banking details have been updated due to an annual treasury audit.

Attached are the revised banking coordinates for Axis Bank Escrow Account.
Please process the pending INR 14,80,000 disbursement immediately prior to 11:30 AM cutoff.

Confirm once remittance receipt is generated. Do not call, I am currently in a board meeting.

Regards,
Robert Chen
Chief Financial Officer`,
    rawHeaders: `Received: from mail-srv4.exec-finance-corp.xyz (mail-srv4.exec-finance-corp.xyz [103.251.167.22])
  by mx.cyberdefense-org.gov.in with ESMTPS id 8Nm9P124
  for <sneha.patel@cyberdefense-org.gov.in>; Wed, 9 Sep 2026 07:42:10 +0000 (UTC)
From: "Robert Chen (Chief Financial Officer)" <rchen-cfo@exec-finance-corp.xyz>
Reply-To: <cfo.emergency.wire@cock.li>
To: <sneha.patel@cyberdefense-org.gov.in>
Subject: URGENT: Updated Bank Remittance Details - Q3 Vendor Settlement
Date: Wed, 9 Sep 2026 07:41:55 +0000
Message-ID: <20260909074155.8829@exec-finance-corp.xyz>
Authentication-Results: mx.cyberdefense-org.gov.in;
  spf=softfail (sender IP is 103.251.167.22) smtp.mailfrom=exec-finance-corp.xyz;
  dkim=none;
  dmarc=fail (p=quarantine)`,
    threatCategory: 'BEC',
    secondaryCategories: ['IMPERSONATION', 'SOCIAL_ENGINEERING'],
    severity: 'CRITICAL',
    riskScore: 92,
    confidenceScore: 96,
    status: 'PENDING_REVIEW',
    isQuarantined: false,
    isBlocked: false,
    isDefanged: true,
    campaignId: 'CAMPAIGN-0089',
    headers: {
      from: 'rchen-cfo@exec-finance-corp.xyz',
      fromDisplayName: 'Robert Chen (Chief Financial Officer)',
      fromDomain: 'exec-finance-corp.xyz',
      to: 'sneha.patel@cyberdefense-org.gov.in',
      toDisplayName: 'Sneha Patel (Senior Accounts Officer)',
      replyTo: 'cfo.emergency.wire@cock.li',
      replyToDomain: 'cock.li',
      returnPath: 'bounce@exec-finance-corp.xyz',
      returnPathDomain: 'exec-finance-corp.xyz',
      messageId: '<20260909074155.8829@exec-finance-corp.xyz>',
      date: 'Wed, 9 Sep 2026 07:41:55 +0000',
      subject: 'URGENT: Updated Bank Remittance Details - Q3 Vendor Settlement',
      spfHeader: 'softfail (~all triggered for 103.251.167.22)',
      dkimHeader: 'none (no cryptographic signature present)',
      dmarcHeader: 'fail (unaligned domain exec-finance-corp.xyz)',
      receivedHops: [
        {
          hopNumber: 1,
          fromServer: 'vps-node-91.mumbai-isp.net',
          fromIp: '103.251.167.22',
          byServer: 'mx.cyberdefense-org.gov.in',
          timestamp: '2026-09-09T07:42:10Z',
          delaySeconds: 15,
          tlsVersion: 'TLSv1.2',
          isSuspicious: true,
          suspiciousReason: 'Unregistered residential proxy IP sending high-value financial instruction',
          country: 'India',
          city: 'Mumbai',
          asn: 'AS133612',
          org: 'AirJaldi Broadband Networks',
        }
      ],
      originatingIp: '103.251.167.22',
      mimeVersion: '1.0',
      contentType: 'text/plain; charset="UTF-8"',
      identityMismatch: true,
      identityMismatchDetails: 'Sender uses display name of CFO "Robert Chen" from throwaway lookalike domain ".xyz" with Reply-To redirected to anonymous service cock.li'
    },
    auth: {
      spf: {
        status: 'SOFTFAIL',
        domain: 'exec-finance-corp.xyz',
        senderIp: '103.251.167.22',
        aligned: false,
        reason: 'SPF ~all softfail: 103.251.167.22 is outside authorized CIDR block',
      },
      dkim: {
        status: 'NONE',
        domain: 'exec-finance-corp.xyz',
        selector: 'none',
        aligned: false,
        reason: 'No DKIM header found in RFC-822 envelope',
      },
      dmarc: {
        status: 'FAIL',
        policy: 'quarantine',
        disposition: 'quarantine',
        aligned: false,
        reason: 'DMARC alignment failed (neither SPF nor DKIM passed alignment)',
      }
    },
    urls: [],
    attachments: [
      {
        name: 'Revised_AxisBank_Escrow_Instructions.pdf',
        sizeBytes: 142800,
        mimeType: 'application/pdf',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        isSuspicious: true,
        threatVerdict: 'Financial Wire Diversion Document'
      }
    ],
    tags: ['BEC Wire Diversion', 'VIP Impersonation', 'Urgent Settlement', 'Reply-To Mismatch']
  },
  {
    id: 'em-0914',
    caseId: 'CASE-2026-0914',
    timestamp: '2026-09-09T06:20:05Z',
    subject: 'Quick task - Are you available at your desk?',
    senderName: 'Vikram Malhotra (Director General)',
    senderAddress: 'dg.vikram.malhotra.official@gmail.com',
    recipientAddress: 'rahul.verma@cyberdefense-org.gov.in',
    previewText: 'Rahul, I am in a confidential ministerial briefing. I need you to procure 10 Apple e-gift vouchers for VIP foreign delegates right now.',
    bodyText: `Rahul,

Are you at your desk right now?

I am currently in an ongoing closed-door ministerial briefing and cannot take calls.
I need you to urgently procure 10 x ₹10,000 Apple App Store electronic gift cards for our visiting foreign delegation.

Send the digital gift codes directly to my personal WhatsApp at +91-98200XXXXX or reply to this email immediately.
I will authorize the official reimbursement claim first thing tomorrow morning.

Do this discreetly.

Best regards,
Dr. Vikram Malhotra
Director General`,
    rawHeaders: `Received: from mail-ed1-f42.google.com (mail-ed1-f42.google.com [209.85.208.42])
  by mx.cyberdefense-org.gov.in with ESMTPS id 3Jk1Q990
  for <rahul.verma@cyberdefense-org.gov.in>; Wed, 9 Sep 2026 06:20:05 +0000 (UTC)
From: "Vikram Malhotra (Director General)" <dg.vikram.malhotra.official@gmail.com>
To: <rahul.verma@cyberdefense-org.gov.in>
Subject: Quick task - Are you available at your desk?
Date: Wed, 9 Sep 2026 06:19:40 +0000
Message-ID: <CAE_vM=8910kQ@mail.gmail.com>
Authentication-Results: mx.cyberdefense-org.gov.in;
  spf=pass (google.com) smtp.mailfrom=dg.vikram.malhotra.official@gmail.com;
  dkim=pass header.d=gmail.com;
  dmarc=pass header.from=gmail.com`,
    threatCategory: 'IMPERSONATION',
    secondaryCategories: ['SOCIAL_ENGINEERING'],
    severity: 'HIGH',
    riskScore: 81,
    confidenceScore: 91,
    status: 'PENDING_REVIEW',
    isQuarantined: false,
    isBlocked: false,
    isDefanged: false,
    headers: {
      from: 'dg.vikram.malhotra.official@gmail.com',
      fromDisplayName: 'Vikram Malhotra (Director General)',
      fromDomain: 'gmail.com',
      to: 'rahul.verma@cyberdefense-org.gov.in',
      toDisplayName: 'Rahul Verma (Executive Assistant)',
      returnPath: 'dg.vikram.malhotra.official@gmail.com',
      returnPathDomain: 'gmail.com',
      messageId: '<CAE_vM=8910kQ@mail.gmail.com>',
      date: 'Wed, 9 Sep 2026 06:19:40 +0000',
      subject: 'Quick task - Are you available at your desk?',
      spfHeader: 'pass (google.com authenticates mail)',
      dkimHeader: 'pass (valid signature for gmail.com)',
      dmarcHeader: 'pass (aligned with freemail provider)',
      receivedHops: [
        {
          hopNumber: 1,
          fromServer: 'mail-ed1-f42.google.com',
          fromIp: '209.85.208.42',
          byServer: 'mx.cyberdefense-org.gov.in',
          timestamp: '2026-09-09T06:20:05Z',
          delaySeconds: 25,
          tlsVersion: 'TLSv1.3',
          isSuspicious: false,
          country: 'United States',
          city: 'Mountain View',
          asn: 'AS15169',
          org: 'Google LLC',
        }
      ],
      originatingIp: '209.85.208.42',
      mimeVersion: '1.0',
      contentType: 'text/plain; charset="UTF-8"',
      identityMismatch: true,
      identityMismatchDetails: 'Free public webmail (@gmail.com) account used to impersonate internal Director General "Dr. Vikram Malhotra". High executive impersonation risk.'
    },
    auth: {
      spf: {
        status: 'PASS',
        domain: 'gmail.com',
        senderIp: '209.85.208.42',
        aligned: true,
        reason: 'SPF passed technically for free Gmail domain',
      },
      dkim: {
        status: 'PASS',
        domain: 'gmail.com',
        selector: '20230601',
        aligned: true,
        reason: 'DKIM signature valid for gmail.com domain',
      },
      dmarc: {
        status: 'PASS',
        policy: 'none',
        disposition: 'none',
        aligned: true,
        reason: 'DMARC pass on generic consumer webmail, masking corporate impersonation',
      }
    },
    urls: [],
    attachments: [],
    tags: ['Executive Impersonation', 'Freemail Abuse', 'Gift Card Lure', 'Secrecy Request']
  },
  {
    id: 'em-0775',
    caseId: 'CASE-2026-0775',
    timestamp: '2026-09-09T05:10:14Z',
    subject: 'Enterprise Security Awareness Training - Q3 Module Now Open',
    senderName: 'Cyberdefense SecOps Team',
    senderAddress: 'security-training@cyberdefense-org.gov.in',
    recipientAddress: 'all-staff@cyberdefense-org.gov.in',
    previewText: 'Team, please complete your mandatory Q3 cyber defense hygiene interactive module on the official staff portal before September 30.',
    bodyText: `Dear Colleagues,

The Q3 2026 mandatory Cybersecurity Awareness Training module is now live on our internal learning management system.

Module highlights:
1. Recognizing spear phishing and display name spoofing
2. Reporting anomalous emails to MAILTRACE SOC
3. Handling institutional data securely

Access the portal: https://lms.cyberdefense-org.gov.in/modules/q3-2026

Completion deadline: September 30, 2026.

Thank you for keeping our organization resilient.

Cybersecurity Operations Team
cyberdefense-org.gov.in`,
    rawHeaders: `Received: from internal-smtp-01.cyberdefense-org.gov.in (internal-smtp-01.cyberdefense-org.gov.in [198.51.100.14])
  by mx.cyberdefense-org.gov.in with ESMTPS id 1Zq9L334
  for <all-staff@cyberdefense-org.gov.in>; Wed, 9 Sep 2026 05:10:14 +0000 (UTC)
From: "Cyberdefense SecOps Team" <security-training@cyberdefense-org.gov.in>
To: <all-staff@cyberdefense-org.gov.in>
Subject: Enterprise Security Awareness Training - Q3 Module Now Open
Date: Wed, 9 Sep 2026 05:10:02 +0000
Message-ID: <20260909051002.5511@cyberdefense-org.gov.in>
Authentication-Results: mx.cyberdefense-org.gov.in;
  spf=pass (sender IP is 198.51.100.14) smtp.mailfrom=security-training@cyberdefense-org.gov.in;
  dkim=pass header.d=cyberdefense-org.gov.in;
  dmarc=pass (p=reject) header.from=cyberdefense-org.gov.in`,
    threatCategory: 'BENIGN',
    severity: 'LOW',
    riskScore: 4,
    confidenceScore: 98,
    status: 'INVESTIGATED',
    isQuarantined: false,
    isBlocked: false,
    isDefanged: false,
    headers: {
      from: 'security-training@cyberdefense-org.gov.in',
      fromDisplayName: 'Cyberdefense SecOps Team',
      fromDomain: 'cyberdefense-org.gov.in',
      to: 'all-staff@cyberdefense-org.gov.in',
      returnPath: 'security-training@cyberdefense-org.gov.in',
      returnPathDomain: 'cyberdefense-org.gov.in',
      messageId: '<20260909051002.5511@cyberdefense-org.gov.in>',
      date: 'Wed, 9 Sep 2026 05:10:02 +0000',
      subject: 'Enterprise Security Awareness Training - Q3 Module Now Open',
      spfHeader: 'pass (IP 198.51.100.14 authorized)',
      dkimHeader: 'pass (valid internal key signature)',
      dmarcHeader: 'pass (strict alignment achieved)',
      receivedHops: [
        {
          hopNumber: 1,
          fromServer: 'internal-smtp-01.cyberdefense-org.gov.in',
          fromIp: '198.51.100.14',
          byServer: 'mx.cyberdefense-org.gov.in',
          timestamp: '2026-09-09T05:10:14Z',
          delaySeconds: 1,
          tlsVersion: 'TLSv1.3',
          isSuspicious: false,
          country: 'India',
          city: 'New Delhi',
          asn: 'AS55836',
          org: 'National Informatics Centre',
        }
      ],
      originatingIp: '198.51.100.14',
      mimeVersion: '1.0',
      contentType: 'text/plain; charset="UTF-8"',
      identityMismatch: false,
    },
    auth: {
      spf: {
        status: 'PASS',
        domain: 'cyberdefense-org.gov.in',
        senderIp: '198.51.100.14',
        aligned: true,
        reason: 'Authorized internal mail relay server subnet',
      },
      dkim: {
        status: 'PASS',
        domain: 'cyberdefense-org.gov.in',
        selector: 's2026',
        aligned: true,
        reason: '2048-bit RSA signature verified and aligned with Header-From',
      },
      dmarc: {
        status: 'PASS',
        policy: 'reject',
        disposition: 'none',
        aligned: true,
        reason: 'Strict DMARC pass with both SPF and DKIM 100% aligned',
      }
    },
    urls: [
      {
        originalUrl: 'https://lms.cyberdefense-org.gov.in/modules/q3-2026',
        defangedUrl: 'https://lms.cyberdefense-org.gov.in/modules/q3-2026',
        domain: 'lms.cyberdefense-org.gov.in',
        registrableDomain: 'cyberdefense-org.gov.in',
        ip: '198.51.100.14',
        asn: 'AS55836',
        asnOrg: 'National Informatics Centre',
        country: 'India',
        isPunycode: false,
        hasSuspiciousKeyword: false,
        isShortener: false,
        isCredentialPath: false,
        reputationScore: 0,
        threatTags: ['Internal Corporate Domain', 'Verified HTTPS TLSv1.3']
      }
    ],
    attachments: [],
    tags: ['Internal Verified', 'False-Positive Baseline', 'Compliant Auth']
  },
  {
    id: 'em-0933',
    caseId: 'CASE-2026-0933',
    timestamp: '2026-09-09T04:12:00Z',
    subject: 'Overdue Invoice INV-948192 attached - Immediate settlement requested',
    senderName: 'Global Cloud Billing Services',
    senderAddress: 'billing@cloud-billing-portal.org',
    recipientAddress: 'procurement@cyberdefense-org.gov.in',
    previewText: 'Attached is past-due Invoice INV-948192. Please scan the verification QR code inside the document to complete authorization.',
    bodyText: `Dear Customer,

Your cloud hosting infrastructure subscription invoice #INV-948192 is 14 days overdue.

To avoid automated server decommissioning and data forfeiture, please open the attached PDF statement and scan the Instant Authorization QR Code using your corporate authenticator app.

Payment Link: https://auth-billing.online/qr-pay/session?id=INV948192

Accounting Department
Cloud Billing Infrastructure`,
    rawHeaders: `Received: from mail.cloud-billing-portal.org (mail.cloud-billing-portal.org [45.142.120.18])
  by mx.cyberdefense-org.gov.in with ESMTPS id 7Kx3R119
  for <procurement@cyberdefense-org.gov.in>; Wed, 9 Sep 2026 04:12:00 +0000 (UTC)
From: "Global Cloud Billing Services" <billing@cloud-billing-portal.org>
To: <procurement@cyberdefense-org.gov.in>
Subject: Overdue Invoice INV-948192 attached - Immediate settlement requested
Date: Wed, 9 Sep 2026 04:11:45 +0000
Message-ID: <20260909041145.4812@cloud-billing-portal.org>
Authentication-Results: mx.cyberdefense-org.gov.in;
  spf=fail (IP 45.142.120.18 not authorized);
  dkim=fail;
  dmarc=fail`,
    threatCategory: 'QUISHING',
    secondaryCategories: ['CREDENTIAL_HARVESTING', 'PHISHING'],
    severity: 'HIGH',
    riskScore: 76,
    confidenceScore: 89,
    status: 'PENDING_REVIEW',
    isQuarantined: false,
    isBlocked: false,
    isDefanged: true,
    headers: {
      from: 'billing@cloud-billing-portal.org',
      fromDisplayName: 'Global Cloud Billing Services',
      fromDomain: 'cloud-billing-portal.org',
      to: 'procurement@cyberdefense-org.gov.in',
      toDisplayName: 'Procurement Cell',
      returnPath: 'bounce@cloud-billing-portal.org',
      returnPathDomain: 'cloud-billing-portal.org',
      messageId: '<20260909041145.4812@cloud-billing-portal.org>',
      date: 'Wed, 9 Sep 2026 04:11:45 +0000',
      subject: 'Overdue Invoice INV-948192 attached - Immediate settlement requested',
      spfHeader: 'fail (sender IP 45.142.120.18 is unlisted)',
      dkimHeader: 'fail (untrusted key signature)',
      dmarcHeader: 'fail (policy reject dis=none)',
      receivedHops: [
        {
          hopNumber: 1,
          fromServer: 'bulletproof-vps.amsterdam-dc.eu',
          fromIp: '45.142.120.18',
          byServer: 'mx.cyberdefense-org.gov.in',
          timestamp: '2026-09-09T04:12:00Z',
          delaySeconds: 15,
          tlsVersion: 'TLSv1.2',
          isSuspicious: true,
          suspiciousReason: 'Originating from known abuse-tolerant hosting ASN in Netherlands',
          country: 'Netherlands',
          city: 'Dronten',
          asn: 'AS57523',
          org: 'Chang Way Technologies Co.',
        }
      ],
      originatingIp: '45.142.120.18',
      mimeVersion: '1.0',
      contentType: 'multipart/mixed',
      identityMismatch: true,
      identityMismatchDetails: 'Generic billing sender claiming infrastructure shutdown with embedded malicious QR redirect link.'
    },
    auth: {
      spf: {
        status: 'FAIL',
        domain: 'cloud-billing-portal.org',
        senderIp: '45.142.120.18',
        aligned: false,
        reason: 'Sender IP 45.142.120.18 is not present in SPF TXT record',
      },
      dkim: {
        status: 'FAIL',
        domain: 'cloud-billing-portal.org',
        selector: 'mail',
        aligned: false,
        reason: 'Public key hash mismatch on selector mail',
      },
      dmarc: {
        status: 'FAIL',
        policy: 'quarantine',
        disposition: 'quarantine',
        aligned: false,
        reason: 'Unauthenticated origin and unaligned Header-From',
      }
    },
    urls: [
      {
        originalUrl: 'https://auth-billing.online/qr-pay/session?id=INV948192',
        defangedUrl: 'hxxps://auth-billing[.]online/qr-pay/session?id=INV948192',
        domain: 'auth-billing.online',
        registrableDomain: 'auth-billing.online',
        ip: '45.142.120.18',
        asn: 'AS57523',
        asnOrg: 'Chang Way Technologies Co.',
        country: 'Netherlands',
        isPunycode: false,
        hasSuspiciousKeyword: true,
        isShortener: false,
        isCredentialPath: true,
        reputationScore: 88,
        threatTags: ['Quishing / QR Capture Lure', 'Decommissioning Threat Language']
      }
    ],
    attachments: [
      {
        name: 'Invoice_948192_PaymentQR.pdf',
        sizeBytes: 284100,
        mimeType: 'application/pdf',
        sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        isSuspicious: true,
        threatVerdict: 'Quishing PDF containing deceptive QR code leading to credential harvesting gateway'
      }
    ],
    tags: ['Quishing Lure', 'QR Phishing', 'Attachment Threat', 'Abuse Host']
  },
  {
    id: 'em-0950',
    caseId: 'CASE-2026-0950',
    timestamp: '2026-09-09T03:30:19Z',
    subject: 'IT Helpdesk: Mandatory MFA Security Token Synchronization',
    senderName: 'IT Central Helpdesk',
    senderAddress: 'support@it-services-desk.online',
    recipientAddress: 'priya.sharma@cyberdefense-org.gov.in',
    previewText: 'All employees are required to resynchronize their multi-factor hardware security key by 12:00 PM today to prevent SSO lockout.',
    bodyText: `Attention Priya,

As part of the nationwide zero-trust identity migration, all employees must resynchronize their MFA software tokens today.

Synchronize your authenticator: https://it-services-desk.online/sso/sync?token=77192

Failure to complete synchronization before 12:00 PM will revoke your VPN profile.

IT Helpdesk Support
Network Operations Group`,
    rawHeaders: `Received: from mail-relay-02.vpn-exit.nl (mail-relay-02.vpn-exit.nl [185.220.101.42])
  by mx.cyberdefense-org.gov.in with ESMTPS id 9Hj4K881
  for <priya.sharma@cyberdefense-org.gov.in>; Wed, 9 Sep 2026 03:30:19 +0000 (UTC)
From: "IT Central Helpdesk" <support@it-services-desk.online>
To: <priya.sharma@cyberdefense-org.gov.in>
Subject: IT Helpdesk: Mandatory MFA Security Token Synchronization
Date: Wed, 9 Sep 2026 03:30:05 +0000
Message-ID: <20260909033005.1190@it-services-desk.online>`,
    threatCategory: 'PHISHING',
    secondaryCategories: ['CREDENTIAL_HARVESTING', 'IMPERSONATION'],
    severity: 'CRITICAL',
    riskScore: 89,
    confidenceScore: 95,
    status: 'PENDING_REVIEW',
    isQuarantined: false,
    isBlocked: false,
    isDefanged: true,
    campaignId: 'CAMPAIGN-0042',
    headers: {
      from: 'support@it-services-desk.online',
      fromDisplayName: 'IT Central Helpdesk',
      fromDomain: 'it-services-desk.online',
      to: 'priya.sharma@cyberdefense-org.gov.in',
      toDisplayName: 'Priya Sharma (HR Operations)',
      returnPath: 'bounce@it-services-desk.online',
      returnPathDomain: 'it-services-desk.online',
      messageId: '<20260909033005.1190@it-services-desk.online>',
      date: 'Wed, 9 Sep 2026 03:30:05 +0000',
      subject: 'IT Helpdesk: Mandatory MFA Security Token Synchronization',
      spfHeader: 'fail (IP 185.220.101.42 unauthorized)',
      dkimHeader: 'fail',
      dmarcHeader: 'fail',
      receivedHops: [
        {
          hopNumber: 1,
          fromServer: 'mail-relay-02.vpn-exit.nl',
          fromIp: '185.220.101.42',
          byServer: 'mx.cyberdefense-org.gov.in',
          timestamp: '2026-09-09T03:30:19Z',
          delaySeconds: 14,
          tlsVersion: 'TLSv1.2',
          isSuspicious: true,
          suspiciousReason: 'Shares identical Tor Exit infrastructure (185.220.101.42) with CASE-2026-0842 in CAMPAIGN-0042',
          country: 'Netherlands',
          city: 'Amsterdam',
          asn: 'AS60729',
          org: 'Zwiebelfreunde Tor Relay Service',
        }
      ],
      originatingIp: '185.220.101.42',
      mimeVersion: '1.0',
      contentType: 'text/html; charset="UTF-8"',
      identityMismatch: true,
      identityMismatchDetails: 'Internal IT Helpdesk impersonation utilizing external Tor infrastructure and disposable ".online" domain.'
    },
    auth: {
      spf: {
        status: 'FAIL',
        domain: 'it-services-desk.online',
        senderIp: '185.220.101.42',
        aligned: false,
        reason: 'SPF lookup failed: 185.220.101.42 not allowed',
      },
      dkim: {
        status: 'FAIL',
        domain: 'it-services-desk.online',
        selector: 'default',
        aligned: false,
        reason: 'DKIM signature missing required canonicalization parameters',
      },
      dmarc: {
        status: 'FAIL',
        policy: 'reject',
        disposition: 'quarantine',
        aligned: false,
        reason: 'DMARC alignment failed',
      }
    },
    urls: [
      {
        originalUrl: 'https://it-services-desk.online/sso/sync?token=77192',
        defangedUrl: 'hxxps://it-services-desk[.]online/sso/sync?token=77192',
        domain: 'it-services-desk.online',
        registrableDomain: 'it-services-desk.online',
        ip: '185.220.101.42',
        asn: 'AS60729',
        asnOrg: 'Zwiebelfreunde Tor Relay Service',
        country: 'Netherlands',
        isPunycode: false,
        hasSuspiciousKeyword: true,
        isShortener: false,
        isCredentialPath: true,
        reputationScore: 94,
        threatTags: ['Correlated IP in CAMPAIGN-0042', 'Fake SSO Sync Portal']
      }
    ],
    attachments: [],
    tags: ['Campaign Linked', 'Tor Infrastructure', 'MFA Lure', 'Multi-Recipient Wave']
  }
];

export const MOCK_EMAILS: EmailRecord[] = RAW_EMAILS.map(e => ({
  ...e,
  authenticationResults: {
    ...e.auth,
    overallAlignment: e.auth.dmarc.aligned,
    spf: { ...e.auth.spf, details: e.auth.spf.reason },
    dkim: { ...e.auth.dkim, details: e.auth.dkim.reason },
    dmarc: { ...e.auth.dmarc, details: e.auth.dmarc.reason }
  },
  extractedUrls: e.urls.map((u: any) => ({ ...u, riskScore: u.reputationScore || 50 })),
  relayHops: (e.headers.receivedHops || []).map((h: any) => ({
    ...h,
    fromHost: h.fromServer || 'gateway.external.net',
    byHost: h.byServer || 'mx.cyberdefense-org.gov.in',
    anomalyReason: h.suspiciousReason
  })),
  infrastructure: {
    originatingIp: e.headers.originatingIp,
    originatingAsn: 'AS49505 (HostRoyale Ltd)',
    originatingOrg: 'Bulletproof Relay Node',
    originatingCountry: 'Netherlands',
    originatingCity: 'Amsterdam',
    originatingLatitude: 52.3702,
    originatingLongitude: 4.8952,
    isProxyOrTor: true
  }
}));

export const mockEmails = MOCK_EMAILS;


