import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { AppHeader } from './AppHeader';

vi.mock('../api/client', () => ({
  api: { health: vi.fn() },
}));

const healthMock = vi.mocked(api.health);

beforeEach(() => {
  healthMock.mockResolvedValue({
    data: { status: 'ok', version: '1.2.4', uptime_ms: 100, preset_count: 6, engine_capabilities: {} },
    latencyMs: 0.42,
  });
});

describe('AppHeader', () => {
  it('shows brand, live health and changes the active laboratory', async () => {
    const onTabChange = vi.fn();
    render(<AppHeader activeTab="ingest" onTabChange={onTabChange} />);

    expect(screen.getByText('MARKDOWNIFY')).toBeInTheDocument();
    expect(screen.getByText('v1.2.4 + DOM Prompt Guard')).toBeInTheDocument();
    expect(await screen.findByText(/0\.42 ms CPU/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /01 HTML-to-Markdown/ })).toHaveAttribute('aria-pressed', 'true');

    await userEvent.click(screen.getByRole('button', { name: /02 Indirect Prompt-/ }));
    expect(onTabChange).toHaveBeenCalledWith('threats');
  });

  it('fails closed to an offline health indicator', async () => {
    healthMock.mockRejectedValue(new Error('connection refused'));
    render(<AppHeader activeTab="benchmarks" onTabChange={vi.fn()} />);
    expect(await screen.findByText('ENGINE OFFLINE')).toHaveAttribute('title', 'connection refused');
    expect(screen.getByRole('button', { name: /03 Web Extraction/ })).toHaveAttribute('aria-pressed', 'true');
  });
});
