import React from 'react';
import { TenantLiveMonitor } from '../components/tenant/TenantLiveMonitor';

export const TenantPage: React.FC = () => {
  return (
    <div className="space-y-4">
      <TenantLiveMonitor />
    </div>
  );
};
