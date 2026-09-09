import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { ThreatHuntingWorkbench } from '../components/hunting/ThreatHuntingWorkbench';
import * as api from '../lib/api';

describe('ThreatHuntingWorkbench Unit & Integration Suite', () => {
  it('renders ThreatHuntingWorkbench with hypotheses list and executes initial hunt', async () => {
    const mockHuntData = {
      status: 'COMPLETED',
      hunt_query: '',
      total_cases_analyzed: 5,
      hypotheses_evaluated: 6,
      results: [
        {
          hypothesis_id: 'SHARED_INFRASTRUCTURE',
          title: 'Cross-Sender Infrastructure Reuse',
          description: 'Shared sending IPs across senders.',
          rationale: 'Detects infrastructure reuse.',
          mitre_technique: 'T1583.001',
          total_matches: 2,
          matched_cases: [
            {
              case_id: 'case-1234',
              filename: 'phish_test.eml',
              sender: 'attacker@evil.com',
              sender_display: 'Admin',
              risk_score: 85,
              risk_label: 'CRITICAL',
              matching_rationale: 'Shares public IP 185.220.101.5',
            },
          ],
          matched_indicators: [
            { type: 'ip', value: '185.220.101.5', cases_affected: 2 },
          ],
          pivot_recommendations: ['Pivot on sending IP 185.220.101.5'],
          confidence: 0.85,
        },
      ],
    };

    vi.spyOn(api, 'executeThreatHunt').mockResolvedValue(mockHuntData as any);

    render(<ThreatHuntingWorkbench onSelectCase={() => {}} />);

    expect(screen.getByText('Threat Hunting Workbench')).toBeInTheDocument();
    expect(screen.getByText('Huntpedia / SpecterOps Framework')).toBeInTheDocument();
    expect(screen.getByText('Shared Infrastructure Reuse')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('Cross-Sender Infrastructure Reuse')).toBeInTheDocument();
      expect(screen.getByText('185.220.101.5')).toBeInTheDocument();
      expect(screen.getByText('phish_test.eml')).toBeInTheDocument();
    });
  });

  it('allows clicking hypothesis button to trigger new hunt query', async () => {
    const huntSpy = vi.spyOn(api, 'executeThreatHunt').mockResolvedValue({
      status: 'COMPLETED',
      hunt_query: '',
      total_cases_analyzed: 3,
      hypotheses_evaluated: 1,
      results: [],
    });

    render(<ThreatHuntingWorkbench onSelectCase={() => {}} />);

    const execSpoofButton = screen.getByText('VIP / Executive Spoofing');
    fireEvent.click(execSpoofButton);

    await waitFor(() => {
      expect(huntSpy).toHaveBeenCalledWith('EXECUTIVE_SPOOFING', '');
    });
  });
});
