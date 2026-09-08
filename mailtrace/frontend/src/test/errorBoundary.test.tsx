import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { ErrorBoundary } from '../components/ui/ErrorBoundary';

const FaultyComponent: React.FC<{ shouldThrow?: boolean }> = ({ shouldThrow = true }) => {
  if (shouldThrow) {
    throw new Error('Simulated component render crash');
  }
  return <div>Safe Child Component Content</div>;
};

describe('ErrorBoundary Resilience Suite', () => {
  it('renders children normally when no error occurs', () => {
    render(
      <ErrorBoundary>
        <FaultyComponent shouldThrow={false} />
      </ErrorBoundary>
    );
    expect(screen.getByText('Safe Child Component Content')).toBeInTheDocument();
  });

  it('catches render crashes and displays cyber fallback UI without blanking screen', () => {
    // Suppress console.error during expected throw
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary fallbackTitle="CUSTOM ERROR TITLE">
        <FaultyComponent shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText('CUSTOM ERROR TITLE')).toBeInTheDocument();
    expect(screen.getByText('RENDER RECOVERY')).toBeInTheDocument();
    expect(screen.getByText('RETURN TO ANALYSIS')).toBeInTheDocument();
    expect(screen.getByText(/A frontend rendering error occurred/i)).toBeInTheDocument();

    consoleErrorSpy.mockRestore();
  });

  it('calls onReset callback when RETURN TO ANALYSIS is clicked', () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const handleReset = vi.fn();

    render(
      <ErrorBoundary onReset={handleReset}>
        <FaultyComponent shouldThrow={true} />
      </ErrorBoundary>
    );

    const resetButton = screen.getByText('RETURN TO ANALYSIS');
    fireEvent.click(resetButton);

    expect(handleReset).toHaveBeenCalledTimes(1);

    consoleErrorSpy.mockRestore();
  });
});
