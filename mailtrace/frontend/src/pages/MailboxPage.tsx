import React, { useState } from 'react';
import { MailFilterBar } from '../components/mailbox/MailFilterBar';
import { MailboxTable } from '../components/mailbox/MailboxTable';
import { EmailPreviewDrawer } from '../components/mailbox/EmailPreviewDrawer';
import { UploadZone } from '../components/upload/UploadZone';
import { useInvestigation } from '../context/InvestigationContext';
import { EmailMetadata } from '../types/email';
import { Inbox, UploadCloud, ChevronDown, ChevronUp, ShieldAlert } from 'lucide-react';

export const MailboxPage: React.FC = () => {
  const { emails, cases, selectAndInvestigate, ingestUploadedCase, setActiveTab } = useInvestigation();
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [previewEmail, setPreviewEmail] = useState<EmailMetadata | null>(null);
  const [showUploadZone, setShowUploadZone] = useState<boolean>(false);

  const filteredEmails = emails.filter(email => {
    const matchedCase = cases.find(c => c.id === email.caseId || c.emailId === email.id);
    const matchesSev =
      selectedSeverity === 'ALL' || matchedCase?.verdict.severity === selectedSeverity;
    const matchesCat =
      selectedCategory === 'ALL' || email.threatCategory === selectedCategory;

    // Multi-attribute indicator search
    const query = searchQuery.trim().toLowerCase();
    const sender = (email as any).sender || (email as any).from || '';
    const senderDomain = (email as any).senderDomain || (email as any).fromDomain || '';
    const recipient = (email as any).recipient || (email as any).to || '';
    const origIp = (matchedCase as any)?.forensicSummary?.originatingIp || (email as any).headers?.originatingIp || '';
    const urls = (email as any).extractedUrls || (email as any).urls || [];

    const matchesSearch =
      query === '' ||
      email.id.toLowerCase().includes(query) ||
      (email.caseId && email.caseId.toLowerCase().includes(query)) ||
      (email.subject && email.subject.toLowerCase().includes(query)) ||
      sender.toLowerCase().includes(query) ||
      senderDomain.toLowerCase().includes(query) ||
      recipient.toLowerCase().includes(query) ||
      origIp.toLowerCase().includes(query) ||
      urls.some((u: any) =>
        (u.originalUrl || u.defangedUrl || u.url || '').toLowerCase().includes(query) ||
        (u.domain || '').toLowerCase().includes(query)
      );

    return matchesSev && matchesCat && matchesSearch;
  });

  const matchedCaseForPreview = previewEmail
    ? cases.find(c => c.id === previewEmail.caseId || c.emailId === previewEmail.id)
    : undefined;

  const handleAnalysisComplete = (res: any) => {
    if (res) {
      const createdCase = ingestUploadedCase(res);
      setShowUploadZone(false);
      selectAndInvestigate(createdCase.id);
    } else {
      setActiveTab('investigation');
    }
  };

  return (
    <div className="space-y-4">
      {/* Triage Mailbox Header with Ingestion Toggle */}
      <div className="p-4 bg-cyber-panel border border-slate-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold font-mono text-slate-100 flex items-center gap-2">
            <Inbox className="w-4 h-4 text-cyan-400" />
            <span>Security Operations Triage Mailbox</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Incoming reported suspicious emails from enterprise mailboxes awaiting SOC forensic triage
          </p>
        </div>

        <button
          onClick={() => setShowUploadZone(!showUploadZone)}
          className="flex items-center gap-2 px-3 py-1.5 rounded bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-bold transition-all shrink-0"
        >
          <UploadCloud className="w-4 h-4 text-cyan-400" />
          <span>{showUploadZone ? 'Hide Ingestion Zone' : '+ Ingest Raw .EML'}</span>
          {showUploadZone ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {/* Collapsible EML Ingestion Dropzone */}
      {showUploadZone && (
        <div className="p-4 rounded-lg bg-cyber-darker border border-cyan-500/30 animate-in fade-in zoom-in-95 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-mono font-bold text-cyan-300 uppercase">
              Drag & Drop .EML Sample for Automated Ingestion
            </span>
            <span className="text-[10px] font-mono text-slate-400">
              MIME Parsing • SPF/DKIM/DMARC • AI Threat Scoring
            </span>
          </div>
          <UploadZone
            onAnalysisComplete={handleAnalysisComplete}
            onUploadSuccess={(res) => {
              if (res) ingestUploadedCase(res);
            }}
            onViewInvestigations={() => setActiveTab('investigation')}
          />
        </div>
      )}

      {/* Filter Bar */}
      <MailFilterBar
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        selectedSeverity={selectedSeverity}
        onSelectSeverity={setSelectedSeverity}
        selectedCategory={selectedCategory}
        onSelectCategory={setSelectedCategory}
        totalCount={filteredEmails.length}
      />

      {/* Security Mailbox Triage Table */}
      <MailboxTable
        emails={filteredEmails}
        cases={cases}
        onSelectEmail={email => setPreviewEmail(email)}
        onInvestigate={caseId => selectAndInvestigate(caseId)}
      />

      {/* Email Preview Drawer */}
      {previewEmail && (
        <EmailPreviewDrawer
          email={previewEmail}
          investigationCase={matchedCaseForPreview}
          onClose={() => setPreviewEmail(null)}
          onInvestigate={caseId => selectAndInvestigate(caseId)}
        />
      )}
    </div>
  );
};
