export type ResponseActionType = 'QUARANTINE' | 'BLOCK_DOMAIN' | 'BLOCK_IP' | 'DEFANG_URL' | 'RELEASE' | 'SUBMIT_ABUSE_REPORT' | 'ADD_BANNER';

export interface ResponseActionLog {
  id: string;
  caseId: string;
  actionType: ResponseActionType;
  target: string;
  status: 'EXECUTED' | 'PENDING' | 'ROLLED_BACK';
  executedBy: string;
  timestamp: string;
  reason: string;
  impactScore: number;
}
