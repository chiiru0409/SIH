import React from 'react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';

interface ShellProps {
  children: React.ReactNode;
}

export const Shell: React.FC<ShellProps> = ({ children }) => {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-cyber-dark text-slate-100 font-sans">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 h-screen overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto cyber-scrollbar p-6 bg-cyber-dark/95">
          {children}
        </main>
      </div>
    </div>
  );
};
