import React from 'react';
import { UploadZone } from '../components/upload/UploadZone';
import { useInvestigation } from '../context/InvestigationContext';

export const UploadPage: React.FC = () => {
  const { setActiveTab, ingestUploadedCase, selectAndInvestigate } = useInvestigation();

  const handleAnalysisComplete = (res: any) => {
    if (res) {
      const createdCase = ingestUploadedCase(res);
      selectAndInvestigate(createdCase.id);
    } else {
      setActiveTab('investigation');
    }
  };

  return (
    <div className="space-y-4 max-w-4xl mx-auto">
      <div className="p-4 bg-cyber-panel border border-slate-800 rounded-lg">
        <h2 className="text-base font-bold font-mono text-slate-100 flex items-center gap-2">
          <span>Live RFC-822 EML File Ingestion & Forensic Analyzer</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Drag and drop any raw <code className="text-cyan-300 font-mono">.eml</code> email sample to execute real-time SHA-256 anchoring, MIME disassembly, SPF/DKIM/DMARC verification, and AI threat scoring.
        </p>
      </div>

      <UploadZone
        onAnalysisComplete={handleAnalysisComplete}
        onUploadSuccess={(res) => {
          if (res) {
            ingestUploadedCase(res);
          }
        }}
        onViewInvestigations={() => {
          setActiveTab('investigation');
        }}
      />
    </div>
  );
};
