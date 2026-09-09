/**
 * api.ts — Centralized typed API client for MailTrace backend.
 * Uses VITE_API_BASE_URL if configured.
 * When not configured, uses same-origin relative endpoints ("").
 */

import type {
  BlockchainAnchorResponse,
  CaseCorrelationDetailResponse,
  CaseDetail,
  CaseSummary,
  ChainOfCustodyResponse,
  CorrelationOverviewResponse,
  EvidenceManifestResponse,
  EvidenceVerifyResponse,
  HealthResponse,
  UploadResponse,
} from '../types/api';

const rawBaseUrl = (import.meta.env.VITE_API_BASE_URL || '').trim();
const API_BASE_URL = rawBaseUrl ? rawBaseUrl.replace(/\/+$/, '') : '';

function buildUrl(endpoint: string): string {
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return `${API_BASE_URL}${cleanEndpoint}`;
}

class ApiError extends Error {
  status: number;
  code?: string;
  detail?: any;

  constructor(message: string, status: number, code?: string, detail?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = buildUrl(endpoint);
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        Accept: 'application/json',
        ...(options?.headers || {}),
      },
    });

    if (!response.ok) {
      let errBody: any;
      try {
        errBody = await response.json();
      } catch {
        errBody = { message: response.statusText };
      }

      const errorDetail = errBody.detail || errBody;
      const message = typeof errorDetail === 'string' 
        ? errorDetail 
        : errorDetail?.message || `Request failed with status ${response.status}`;
      const code = errorDetail?.code || undefined;

      throw new ApiError(message, response.status, code, errorDetail);
    }

    return (await response.json()) as T;
  } catch (error: any) {
    if (error instanceof ApiError) {
      throw error;
    }
    // Network / connection error
    const connectionMsg = import.meta.env.PROD
      ? 'Backend service unavailable. Please check network connection or try again shortly.'
      : 'Backend service unreachable. Ensure the MailTrace backend is running.';
    throw new ApiError(
      connectionMsg,
      0,
      'NETWORK_ERROR',
      error.message
    );
  }
}

// ------------------------------------------------------------------ //
//  API Client Functions                                              //
// ------------------------------------------------------------------ //

/**
 * Check backend liveness & metadata.
 */
export async function checkHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/api/health');
}

/**
 * Check backend database readiness & connection status.
 */
export async function checkReadiness(): Promise<HealthResponse> {
  return request<HealthResponse>('/api/health/ready');
}

/**
 * Upload and forensically analyze an .eml file.
 */
export async function uploadEmail(file: File): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append('file', file, file.name);

  return request<UploadResponse>('/api/analyze/upload', {
    method: 'POST',
    body: formData,
  });
}

/**
 * Fetch paginated list of all analysis cases.
 */
export async function fetchCases(page: number = 1, pageSize: number = 50): Promise<CaseSummary[]> {
  return request<CaseSummary[]>(`/api/analyze/cases?page=${page}&page_size=${pageSize}`);
}

/**
 * Fetch full forensic case record by ID.
 */
export async function fetchCase(caseId: string): Promise<CaseDetail> {
  return request<CaseDetail>(`/api/analyze/${caseId}`);
}

/**
 * Fetch global campaign correlation overview & investigation graph.
 */
export async function fetchGlobalCorrelation(): Promise<CorrelationOverviewResponse> {
  return request<CorrelationOverviewResponse>('/api/correlation');
}

/**
 * Fetch case-specific correlation details, related cases, and sub-graph.
 */
export async function fetchCaseCorrelation(caseId: string): Promise<CaseCorrelationDetailResponse> {
  return request<CaseCorrelationDetailResponse>(`/api/correlation/${caseId}`);
}

// ------------------------------------------------------------------ //
//  Step 9: Evidence Integrity & Blockchain API Calls                 //
// ------------------------------------------------------------------ //

/**
 * Fetch structured evidence manifest for a case.
 */
export async function fetchEvidenceManifest(caseId: string): Promise<EvidenceManifestResponse> {
  return request<EvidenceManifestResponse>(`/api/evidence/${caseId}`);
}

/**
 * Run cryptographic evidence and chain-of-custody verification.
 */
export async function verifyEvidence(caseId: string): Promise<EvidenceVerifyResponse> {
  return request<EvidenceVerifyResponse>(`/api/evidence/${caseId}/verify`);
}

/**
 * Anchor evidence SHA-256 commitment to blockchain ledger.
 */
export async function anchorEvidence(caseId: string): Promise<BlockchainAnchorResponse> {
  return request<BlockchainAnchorResponse>(`/api/evidence/${caseId}/anchor`, {
    method: 'POST',
  });
}

/**
 * Fetch chronological chain-of-custody log for a case.
 */
export async function fetchChainOfCustody(caseId: string): Promise<ChainOfCustodyResponse> {
  return request<ChainOfCustodyResponse>(`/api/evidence/${caseId}/chain`);
}

// ------------------------------------------------------------------ //
//  Enterprise API Calls (Sentaro / GreatHorn / Mimecast)             //
// ------------------------------------------------------------------ //

/**
 * Fetch active cloud tenant configurations (Microsoft 365, Google Workspace).
 */
export async function fetchTenants(): Promise<{ tenants: any[] }> {
  return request<{ tenants: any[] }>('/api/tenants/list');
}

/**
 * Fetch live tenant email threat stream.
 */
export async function fetchTenantStream(): Promise<{ events: any[] }> {
  return request<{ events: any[] }>('/api/tenants/stream');
}

/**
 * Fetch SOC Quarantine Vault items.
 */
export async function fetchQuarantineVault(): Promise<{ quarantined_items: any[] }> {
  return request<{ quarantined_items: any[] }>('/api/policy/quarantine');
}

/**
 * Remediate a quarantined email item (RELEASE, PURGE, BLOCK_SENDER).
 */
export async function remediateQuarantine(caseId: string, action: string, notes?: string): Promise<any> {
  return request<any>(`/api/policy/quarantine/${caseId}/remediate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, notes }),
  });
}

/**
 * Fetch enterprise policy rules.
 */
export async function fetchPolicyRules(): Promise<{ policies: any[] }> {
  return request<{ policies: any[] }>('/api/policy/rules');
}

/**
 * Fetch enterprise blocklist.
 */
export async function fetchBlocklist(): Promise<{ blocklist: any[] }> {
  return request<{ blocklist: any[] }>('/api/policy/blocklist');
}

/**
 * Add entry to enterprise blocklist.
 */
export async function addToBlocklist(type: string, value: string, reason?: string): Promise<any> {
  return request<any>('/api/policy/blocklist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type, value, reason }),
  });
}

/**
 * Fetch regulatory compliance audit scorecard (NIS2, DORA, SOC 2).
 */
export async function fetchComplianceScorecard(): Promise<any> {
  return request<any>('/api/compliance/scorecard');
}
