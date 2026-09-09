import React from 'react';
import { ThreatHuntingWorkbench } from '../components/hunting/ThreatHuntingWorkbench';
import { useInvestigation } from '../context/InvestigationContext';

export const HuntingPage: React.FC = () => {
  const { selectAndInvestigate } = useInvestigation();

  return (
    <div className="space-y-4">
      <ThreatHuntingWorkbench
        onSelectCase={(caseId) => {
          selectAndInvestigate(caseId);
        }}
      />
    </div>
  );
};
