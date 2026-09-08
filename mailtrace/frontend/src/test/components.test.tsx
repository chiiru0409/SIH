import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { RiskScoreHero } from '../components/risk/RiskScoreHero';
import { ThreatClassificationPanel } from '../components/threat/ThreatClassificationPanel';
import { AuthenticationMatrix } from '../components/forensic/AuthenticationMatrix';
import { ForensicEvidencePanel } from '../components/forensic/ForensicEvidencePanel';
import { RiskFactorsList } from '../components/risk/RiskFactorsList';

describe('MailTrace Dashboard Core Component Suite', () => {
  it('renders RiskScoreHero with correct score and severity', () => {
    const mockRisk = {
      risk_score: 85.0,
      severity: 'CRITICAL',
      risk_factors: [],
      category_scores: { authentication: 30, threat_intent: 40 },
      top_factors: [],
      explanation: 'Critical risk detected due to SPF failure and phishing signals.',
      confidence: 0.95,
      limitations: [],
    };

    render(<RiskScoreHero riskAssessment={mockRisk} />);
    expect(screen.getByText('85')).toBeInTheDocument();
    expect(screen.getByText('/ 100 RISK')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL SEVERITY LEVEL')).toBeInTheDocument();
  });

  it('renders ThreatClassificationPanel with primary threat and confidence', () => {
    const mockThreat = {
      primary_threat: 'PHISHING',
      secondary_threats: ['CREDENTIAL_HARVESTING', 'IMPERSONATION'],
      confidence: 0.91,
      signals: {
        urgency: 'HIGH',
        credential_request: 'HIGH',
        financial_request: 'LOW',
        impersonation: 'HIGH',
        suspicious_link: 'HIGH',
        attachment_threat: 'NONE',
        fear_manipulation: 'MEDIUM',
        authority_pressure: 'HIGH',
      },
      indicators: [
        {
          indicator: 'URGENT_ACTION_REQUIRED',
          category: 'urgency',
          weight: 15.0,
          severity: 'HIGH',
          description: 'Demands immediate credential reset within 24 hours',
          evidence: 'Account suspended within 24h',
        },
      ],
      explanation: 'Targeted spear-phishing attack attempting credential harvesting.',
      evidence_summary: {},
    };

    render(<ThreatClassificationPanel threatAnalysis={mockThreat} />);
    expect(screen.getByText('PHISHING')).toBeInTheDocument();
    expect(screen.getByText('91% CONFIDENCE')).toBeInTheDocument();
    expect(screen.getByText('CREDENTIAL_HARVESTING')).toBeInTheDocument();
  });

  it('renders AuthenticationMatrix without converting UNKNOWN to FAIL', () => {
    const mockAuth = {
      spf: 'pass' as const,
      dkim: 'unknown' as const,
      dmarc: 'fail' as const,
    };

    render(<AuthenticationMatrix auth={mockAuth} />);
    expect(screen.getByText('SPF')).toBeInTheDocument();
    expect(screen.getByText('PASS')).toBeInTheDocument();
    expect(screen.getByText('DKIM')).toBeInTheDocument();
    expect(screen.getAllByText('UNKNOWN').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('DMARC')).toBeInTheDocument();
    expect(screen.getByText('FAIL')).toBeInTheDocument();
  });

  it('renders ForensicEvidencePanel distinguishing FACTS and INFERENCES', () => {
    const mockForensics = {
      summary: {
        total_findings: 2,
        facts_count: 1,
        inferences_count: 1,
        highest_severity: 'HIGH',
        authentication_status: 'FAIL',
        identity_status: 'MISMATCH',
      },
      findings: [
        {
          category: 'AUTHENTICATION',
          title: 'SPF Verification Failed',
          type: 'FACT',
          severity: 'HIGH',
          description: 'Envelope sender domain does not authorize sending IP in SPF record.',
          evidence: 'v=spf1 -all',
        },
        {
          category: 'IDENTITY',
          title: 'Brand Impersonation Heuristic',
          type: 'INFERENCE',
          severity: 'HIGH',
          description: 'Display name implies Microsoft Security while domain is third-party.',
          evidence: 'Display name: Microsoft Security',
        },
      ],
      facts: [],
      inferences: [],
      limitations: [],
    };

    render(<ForensicEvidencePanel forensics={mockForensics} />);
    expect(screen.getByText('1 Facts')).toBeInTheDocument();
    expect(screen.getByText('1 Inferences')).toBeInTheDocument();
    expect(screen.getByText('SPF Verification Failed')).toBeInTheDocument();
    expect(screen.getByText('Brand Impersonation Heuristic')).toBeInTheDocument();
  });

  it('renders RiskFactorsList with points and categories', () => {
    const mockFactors = [
      {
        factor: 'Credential Harvesting Intent',
        category: 'threat_intent',
        points: 20,
        severity: 'CRITICAL',
        evidence: 'password reset form detected',
        source: 'NLP_ENGINE',
      },
      {
        factor: 'DMARC Policy Failure',
        category: 'authentication',
        points: 15,
        severity: 'HIGH',
        evidence: 'dmarc=fail (p=reject)',
        source: 'FORENSIC_RULE',
      },
    ];

    render(<RiskFactorsList factors={mockFactors} />);
    expect(screen.getByText('Credential Harvesting Intent')).toBeInTheDocument();
    expect(screen.getByText('+20 pts')).toBeInTheDocument();
    expect(screen.getByText('DMARC Policy Failure')).toBeInTheDocument();
    expect(screen.getByText('+15 pts')).toBeInTheDocument();
  });
});
