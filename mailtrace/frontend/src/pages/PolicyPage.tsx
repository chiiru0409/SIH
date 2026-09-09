import React from 'react';
import { QuarantinePolicyHub } from '../components/policy/QuarantinePolicyHub';
import { DynamicBannerPreview } from '../components/threat/DynamicBannerPreview';

export const PolicyPage: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Dynamic Warning Banners Preview */}
      <div className="p-5 rounded-lg bg-cyber-panel border border-slate-800 space-y-3">
        <h3 className="text-sm font-semibold font-mono text-slate-200">
          In-Message Security Banner Injection Engine
        </h3>
        <p className="text-xs text-slate-400">
          Real-time dynamic warning banners injected into suspicious messages at the gateway boundary to alert employees before interacting with deceptive senders.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
          <DynamicBannerPreview
            banner={{
              title: 'EXTERNAL SENDER: UNCONFIRMED EXECUTIVE IDENTITY',
              message: 'This message originated outside your organization. The display name matches CEO Johnathan Davis, but the sending address is on a newly registered external domain.',
              severity: 'WARNING',
              color: '#f59e0b',
              bg_color: 'rgba(245, 158, 11, 0.1)',
              border_color: 'rgba(245, 158, 11, 0.4)',
              html_injected: '<div>WARNING: EXTERNAL SENDER</div>',
              plaintext_injected: '[WARNING: EXTERNAL SENDER]',
              tags: ['VIP Impersonation', 'First-Time Sender', 'External Domain']
            }}
          />
          <DynamicBannerPreview
            banner={{
              title: 'CRITICAL SECURITY ALERT: SUSPECTED CREDENTIAL HARVESTING',
              message: 'MailTrace AI detected an unauthenticated landing page claiming to be Microsoft 365. Do not enter your passwords or MFA verification codes.',
              severity: 'CRITICAL',
              color: '#ef4444',
              bg_color: 'rgba(239, 68, 68, 0.1)',
              border_color: 'rgba(239, 68, 68, 0.4)',
              html_injected: '<div>CRITICAL: PHISHING LURE</div>',
              plaintext_injected: '[CRITICAL: PHISHING LURE]',
              tags: ['Phishing Lure', 'MFA Harvest', 'Tor Relay']
            }}
          />
        </div>
      </div>

      {/* Quarantine Policy & Rule Hub */}
      <QuarantinePolicyHub />
    </div>
  );
};
