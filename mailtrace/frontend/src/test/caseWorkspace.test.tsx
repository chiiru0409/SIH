import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { CaseDetailWorkspace } from '../components/cases/CaseDetailWorkspace';
import { CaseListView } from '../components/cases/CaseListView';
import { InvestigationGraphView } from '../components/graph/InvestigationGraphView';
import type { CaseDetail, CaseSummary } from '../types/api';

describe('CaseDetailWorkspace & Component Hardening Suite', () => {
  const mockCompleteCase: CaseDetail = {
    case_id: '11111111-2222-3333-4444-555555555555',
    original_filename: 'casual_test.eml',
    evidence_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    status: 'completed',
    risk_score: 45.0,
    risk_label: 'MEDIUM',
    created_at: '2026-09-08T18:00:00Z',
    updated_at: '2026-09-08T18:00:00Z',
    campaign_id: null,
    correlation_data: null,
    report_path: null,
    error_detail: null,
    parsed_email: {
      headers: {
        subject: 'Urgent Security Update',
        from: 'security@example.com',
        from_display: 'Security Admin',
        reply_to: 'security@example.com',
        to: ['user@victim.com'],
        cc: [],
        date: '2026-09-08T18:00:00Z',
        message_id: '<msg-1234@example.com>',
      },
      sender: {
        email: 'security@example.com',
        display_name: 'Security Admin',
        domain: 'example.com',
      },
      recipients: {
        to: ['user@victim.com'],
        cc: [],
      },
      authentication: {
        spf: 'pass',
        dkim: 'pass',
        dmarc: 'pass',
      },
      received_chain: {
        hop_count: 0,
        chain: [],
        public_ips_observed: [],
        earliest_observed_node: null,
      },
      body: 'Please review your account settings.',
      html_body: null,
      raw_headers: {
        From: 'security@example.com',
        To: 'user@victim.com',
        Subject: 'Urgent Security Update',
      },
    },
    risk_reasons: {
      risk_score: 45.0,
      severity: 'MEDIUM',
      risk_factors: [
        {
          factor: 'Urgency Language Detected',
          category: 'threat_intent',
          points: 20,
          severity: 'MEDIUM',
          evidence: 'urgent keyword in subject',
          source: 'NLP_ENGINE',
        },
      ],
      category_scores: {
        authentication: 0,
        identity: 10,
        infrastructure: 15,
        threat_intent: 20,
      },
      top_factors: [],
      explanation: 'Moderate risk due to urgency heuristics.',
      confidence: 0.88,
      limitations: [],
    },
    forensic_analysis: {
      summary: {
        total_findings: 1,
        facts_count: 1,
        inferences_count: 0,
        highest_severity: 'MEDIUM',
        authentication_status: 'PASS',
        identity_status: 'ALIGNED',
      },
      findings: [
        {
          category: 'IDENTITY',
          title: 'Display Name Matches Sender',
          type: 'FACT',
          severity: 'LOW',
          description: 'Sender domain matches display name context.',
          evidence: 'From: Security Admin <security@example.com>',
        },
      ],
      facts: [],
      inferences: [],
      limitations: [],
    },
    ai_analysis: {
      primary_threat: 'SUSPICIOUS',
      secondary_threats: [],
      confidence: 0.85,
      signals: {
        urgency: 'MEDIUM',
        credential_request: 'LOW',
        financial_request: 'NONE',
        impersonation: 'LOW',
        suspicious_link: 'NONE',
        attachment_threat: 'NONE',
        fear_manipulation: 'NONE',
        authority_pressure: 'LOW',
      },
      indicators: [],
      explanation: 'Suspicious email detected.',
      evidence_summary: {},
    },
    ip_intel: { ips: [] },
    domain_intel: { domains: [] },
    url_intel: { urls: [] },
  };

  it('renders CaseDetailWorkspace without error with complete case', () => {
    const handleBack = vi.fn();
    render(
      <CaseDetailWorkspace
        caseData={mockCompleteCase}
        onBack={handleBack}
      />
    );

    expect(screen.getByText(/casual_test\.eml/)).toBeInTheDocument();
    expect(screen.getByText('Urgent Security Update')).toBeInTheDocument();
    expect(screen.getByText('Back to Cases')).toBeInTheDocument();
  });

  it('renders CaseDetailWorkspace safely with minimal/partial/null nested fields', () => {
    const minimalCase: CaseDetail = {
      case_id: '22222222-3333-4444-5555-666666666666',
      original_filename: 'minimal.eml',
      status: 'completed',
      risk_score: 10.0,
      risk_label: 'LOW',
      created_at: '2026-09-08T18:00:00Z',
      updated_at: '2026-09-08T18:00:00Z',
      parsed_email: null,
      forensic_analysis: null,
      ai_analysis: null,
      ip_intel: null,
      domain_intel: null,
      url_intel: null,
      risk_reasons: null,
      campaign_id: null,
      correlation_data: null,
      report_path: null,
      evidence_hash: null,
      error_detail: null,
    };

    const { container } = render(
      <CaseDetailWorkspace
        caseData={minimalCase}
        correlationData={null}
        onBack={() => {}}
      />
    );

    expect(container).toBeInTheDocument();
    expect(screen.getByText(/minimal\.eml/)).toBeInTheDocument();
  });

  it('renders CaseListView with duplicate filenames using unique case_id keys', () => {
    const duplicateCases: CaseSummary[] = [
      {
        case_id: 'aaaa-1111',
        original_filename: 'casual_test.eml',
        status: 'completed',
        risk_score: 4,
        risk_label: 'LOW',
        created_at: '2026-09-08T18:59:53Z',
      },
      {
        case_id: 'bbbb-2222',
        original_filename: 'casual_test.eml',
        status: 'completed',
        risk_score: 4,
        risk_label: 'LOW',
        created_at: '2026-09-08T18:59:37Z',
      },
      {
        case_id: 'cccc-3333',
        original_filename: 'casual_test.eml',
        status: 'completed',
        risk_score: 4,
        risk_label: 'LOW',
        created_at: '2026-09-08T18:59:15Z',
      },
    ];

    const handleSelectCase = vi.fn();

    render(
      <CaseListView
        cases={duplicateCases}
        onSelectCase={handleSelectCase}
      />
    );

    // All 3 items should be rendered
    const filenames = screen.getAllByText('casual_test.eml');
    expect(filenames).toHaveLength(3);

    // Verify IDs are distinct
    expect(screen.getByText(/aaaa-111/)).toBeInTheDocument();
    expect(screen.getByText(/bbbb-222/)).toBeInTheDocument();
    expect(screen.getByText(/cccc-333/)).toBeInTheDocument();

    // Clicking the second one calls handleSelectCase with its unique case_id
    fireEvent.click(filenames[1]);
    expect(handleSelectCase).toHaveBeenCalledWith('bbbb-2222');
  });

  it('renders InvestigationGraphView with 0 nodes without error or NaN', () => {
    const emptyGraph = {
      nodes: [],
      edges: [],
    };

    const { container } = render(
      <InvestigationGraphView graph={emptyGraph} />
    );

    expect(container).toBeInTheDocument();
    expect(screen.getByText('NO GRAPH RELATIONSHIPS AVAILABLE')).toBeInTheDocument();
  });

  it('renders InvestigationGraphView with 1 node without division by zero', () => {
    const singleNodeGraph = {
      nodes: [
        {
          id: 'node-case-1',
          label: 'casual_test.eml',
          type: 'CASE' as const,
          threat_level: 'LOW' as const,
        },
      ],
      edges: [],
    };

    const { container } = render(
      <InvestigationGraphView graph={singleNodeGraph} />
    );

    expect(container).toBeInTheDocument();
    expect(screen.getByText('casual_test.eml')).toBeInTheDocument();
  });
});
