import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { RelayTimeline } from '../components/forensic/RelayTimeline';
import { AuthenticationMatrix } from '../components/forensic/AuthenticationMatrix';
import { ThreatClassificationPanel } from '../components/threat/ThreatClassificationPanel';
import { RiskScoreHero } from '../components/risk/RiskScoreHero';

describe('UI Forensic Data-Integrity & Consistency Tests', () => {
  it('renders RelayTimeline with cautious wording when no Received headers exist', () => {
    render(<RelayTimeline smtpTrace={null} />);
    expect(
      screen.getByText('No Received headers were observed in the supplied message. Relay-path reconstruction is unavailable.')
    ).toBeInTheDocument();

    const emptyTrace = {
      hop_count: 0,
      received_chain: [],
      public_ips: [],
      earliest_node: null,
      confidence_note: 'No Received headers',
    };
    render(<RelayTimeline smtpTrace={emptyTrace} />);
    expect(
      screen.getAllByText('No Received headers were observed in the supplied message. Relay-path reconstruction is unavailable.').length
    ).toBeGreaterThanOrEqual(1);
  });

  it('renders AuthenticationMatrix with UNRECORDED and UNKNOWN instead of false FAIL', () => {
    const unobservedAuth = {
      spf: { status: 'unknown', raw: null },
      dkim: { status: 'unknown', domain: null, selector: null },
      dmarc: { status: 'unknown', policy: null },
    };

    render(<AuthenticationMatrix auth={unobservedAuth as any} alignment={null} />);
    
    // Check that UNKNOWN badges are shown
    const unknownBadges = screen.getAllByText('UNKNOWN');
    expect(unknownBadges.length).toBeGreaterThanOrEqual(3);

    // Check that policy evaluation displays UNRECORDED
    expect(screen.getByText('UNRECORDED')).toBeInTheDocument();
  });

  it('renders AuthenticationMatrix DMARC policy correctly when policy is published', () => {
    const dmarcPolicyAuth = {
      spf: { status: 'pass' },
      dkim: { status: 'pass' },
      dmarc: { status: 'unknown', policy: 'reject' },
    };

    render(<AuthenticationMatrix auth={dmarcPolicyAuth as any} alignment={{ dmarc_pass: false } as any} />);
    expect(screen.getByText('POLICY: REJECT')).toBeInTheDocument();
  });

  it('renders ThreatClassificationPanel without crashing on isolated urgency and benign classification', () => {
    const mockThreat = {
      primary_threat: 'BENIGN',
      secondary_threats: [],
      confidence: 0.75,
      signals: {
        urgency: 'medium',
        credential_request: 'none',
        financial_request: 'none',
        impersonation: 'none',
        suspicious_link: 'none',
        attachment_threat: 'none',
        fear_manipulation: 'none',
        authority_pressure: 'none',
      },
      indicators: [
        {
          indicator: 'urgency_language',
          category: 'urgency',
          weight: 0.7,
          severity: 'medium',
          description: 'Urgency indicator detected: Urgent notification flag.',
          evidence: 'Urgent attention required',
        },
      ],
      explanation:
        "The email from 'test@example.com' with subject 'Sync' exhibits standard communication patterns with low aggregate risk. Isolated minor observations were identified (medium-level urgency language ('Urgent attention required')), but remain below actionable malicious thresholds in isolation. No credential solicitation, financial fraud patterns, deceptive links, dangerous attachments were detected.",
      evidence_summary: {
        facts: ["Sender From header address is 'test@example.com'."],
        inferences: ['Inference: Urgency indicator detected.'],
      },
      analysis_method: 'local',
      model_info: 'rule-nlp-engine-v1',
    };

    render(<ThreatClassificationPanel threatAnalysis={mockThreat} />);
    expect(screen.getByText('BENIGN')).toBeInTheDocument();
    expect(screen.getByText(/medium-level urgency language/i)).toBeInTheDocument();
  });
});
