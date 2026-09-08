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
