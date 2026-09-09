import React from 'react';
import { ComplianceAuditPanel } from '../components/compliance/ComplianceAuditPanel';

export const CompliancePage: React.FC = () => {
  return (
    <div className="space-y-4">
      <ComplianceAuditPanel />
    </div>
  );
};
