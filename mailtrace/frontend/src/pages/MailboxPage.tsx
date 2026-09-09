import React, { useState } from 'react';
import { MailFilterBar } from '../components/mailbox/MailFilterBar';
import { MailboxTable } from '../components/mailbox/MailboxTable';
import { EmailPreviewDrawer } from '../components/mailbox/EmailPreviewDrawer';
import { useInvestigation } from '../../src/context/InvestigationContext';
import { EmailMetadata } from '../types/email';

export const MailboxPage: React.FC = () => {
  const { emails, cases, selectAndInvestigate } = useInvestigation();
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [previewEmail, setPreviewEmail] = useState<EmailMetadata | null>(null);

  const filteredEmails = emails.filter(email => {
    const matchedCase = cases.find(c => c.id === email.caseId || c.emailId === email.id);
    const matchesSev =
      selectedSeverity === 'ALL' || matchedCase?.verdict.severity === selectedSeverity;
    const matchesCat =
      selectedCategory === 'ALL' || email.threatCategory === selectedCategory;
    return matchesSev && matchesCat;
  });

  const matchedCaseForPreview = previewEmail
    ? cases.find(c => c.id === previewEmail.caseId || c.emailId === previewEmail.id)
    : undefined;

  return (
    <div className="space-y-4">
      <MailFilterBar
        selectedSeverity={selectedSeverity}
        onSelectSeverity={setSelectedSeverity}
        selectedCategory={selectedCategory}
        onSelectCategory={setSelectedCategory}
        totalCount={filteredEmails.length}
      />

      <MailboxTable
        emails={filteredEmails}
        cases={cases}
        onSelectEmail={email => setPreviewEmail(email)}
        onInvestigate={caseId => selectAndInvestigate(caseId)}
      />

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
