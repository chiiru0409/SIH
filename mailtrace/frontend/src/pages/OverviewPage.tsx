import React from 'react';
import { KpiCards } from '../components/overview/KpiCards';
import { ThreatTimeline } from '../components/overview/ThreatTimeline';
import { ThreatDistribution } from '../components/overview/ThreatDistribution';
import { RecentIncidents } from '../components/overview/RecentIncidents';
import { ActiveCampaignsCard } from '../components/overview/ActiveCampaignsCard';

export const OverviewPage: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Top Metrics Row */}
      <KpiCards />

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8">
          <ThreatTimeline />
        </div>
        <div className="lg:col-span-4">
          <ThreatDistribution />
        </div>
      </div>

      {/* Recent Incidents & Campaigns Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8">
          <RecentIncidents />
        </div>
        <div className="lg:col-span-4">
          <ActiveCampaignsCard />
        </div>
      </div>
    </div>
  );
};
