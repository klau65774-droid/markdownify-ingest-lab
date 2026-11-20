import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from 'react';
import { AlertTriangle, LoaderCircle, RotateCw } from 'lucide-react';

export const cx = (...classes: Array<string | false | null | undefined>) => classes.filter(Boolean).join(' ');

export type Tone = 'cyan' | 'emerald' | 'rose' | 'amber' | 'slate';

const toneClasses: Record<Tone, string> = {
  cyan: 'border-cyan/30 bg-cyan/10 text-cyan',
  emerald: 'border-emerald/30 bg-emerald/10 text-emerald',
  rose: 'border-rose/30 bg-rose/10 text-rose',
  amber: 'border-amber/30 bg-amber/10 text-amber',
  slate: 'border-slate-700/60 bg-slate-800/40 text-slate-400',
};

export function Panel({
  title,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cx('panel', className)}>
      {(title || actions) && (
        <div className="flex min-h-8 items-center justify-between gap-2 border-b border-border/80 px-3 py-1.5">
          {title && <h2 className="truncate text-[9px] font-semibold uppercase tracking-[0.075em] text-slate-400">{title}</h2>}
          {actions && <div className="flex flex-none items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className={cx('min-w-0', bodyClassName)}>{children}</div>
    </section>
  );
}

export function StatusBadge({ children, tone = 'slate', dot = false, className }: {
  children: ReactNode;
  tone?: Tone;
  dot?: boolean;
  className?: string;
}) {
  return (
    <span className={cx('inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 font-mono text-[8px] font-semibold uppercase leading-3 tracking-[0.035em]', toneClasses[tone], className)}>
      {dot && <span className="h-1 w-1 rounded-full bg-current" />}
      {children}
    </span>
  );
}

export function Button({ className, variant = 'secondary', type = 'button', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
}) {
  const variants = {
    primary: 'border-cyan/70 bg-cyan text-[#041017] shadow-[0_0_20px_rgba(6,182,212,0.16)] hover:bg-cyan/90 hover:shadow-[0_0_24px_rgba(6,182,212,0.24)]',
    secondary: 'border-border bg-raised text-slate-300 hover:border-slate-600 hover:bg-slate-700/40 hover:text-slate-100',
    ghost: 'border-transparent bg-transparent text-slate-500 hover:bg-white/[0.03] hover:text-slate-300',
    danger: 'border-rose/40 bg-rose/10 text-rose hover:bg-rose/20',
  };
  return (
    <button
      type={type}
      className={cx('inline-flex items-center justify-center gap-2 rounded border px-3 py-2 text-[10px] font-semibold tracking-[0.025em] transition-all disabled:cursor-not-allowed disabled:opacity-50', variants[variant], className)}
      {...props}
    />
  );
}

export function Toggle({ label, checked, onChange, disabled = false }: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="group flex w-full items-center justify-between gap-3 py-[7px] text-left disabled:opacity-50"
    >
      <span className="text-[10px] leading-4 text-slate-400 transition-colors group-hover:text-slate-300">{label}</span>
      <span className={cx('relative h-[13px] w-[25px] flex-none rounded-full border transition-colors', checked ? 'border-cyan bg-cyan shadow-[0_0_9px_rgba(6,182,212,0.25)]' : 'border-slate-600 bg-slate-700')}>
        <span className={cx('absolute top-[2px] h-[7px] w-[7px] rounded-full bg-white transition-all', checked ? 'left-[15px]' : 'left-[2px]')} />
      </span>
    </button>
  );
}

export function MetricRow({ label, value, tone = 'slate' }: { label: ReactNode; value: ReactNode; tone?: Tone }) {
  const valueColors: Record<Tone, string> = {
    cyan: 'text-cyan', emerald: 'text-emerald', rose: 'text-rose', amber: 'text-amber', slate: 'text-slate-300',
  };
  return (
    <div className="flex items-center justify-between gap-3 border-b border-border/50 py-3 last:border-0">
      <span className="text-[10px] leading-4 text-slate-400">{label}</span>
      <span className={cx('text-right font-mono text-[10px] font-medium', valueColors[tone])}>{value}</span>
    </div>
  );
}

export function LoadingState({ label = 'CONTACTING INGEST ENGINE' }: { label?: string }) {
  return (
    <div className="flex min-h-28 flex-col items-center justify-center gap-3 p-5 text-center">
      <LoaderCircle size={19} className="animate-spin text-cyan" aria-hidden="true" />
      <span className="font-mono text-[9px] tracking-[0.08em] text-slate-500">{label}</span>
    </div>
  );
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="flex min-h-24 flex-col items-center justify-center gap-1.5 p-5 text-center">
      <span className="font-mono text-[10px] uppercase tracking-[0.06em] text-slate-500">{title}</span>
      <span className="max-w-sm text-[10px] leading-4 text-slate-600">{detail}</span>
    </div>
  );
}

export function ErrorState({ message, onRetry, retryLabel = 'Retry connection' }: {
  message: string;
  onRetry?: () => void;
  retryLabel?: string;
}) {
  return (
    <div role="alert" className="m-3 flex items-start gap-3 rounded border border-rose/25 bg-rose/[0.06] p-3">
      <AlertTriangle size={15} className="mt-0.5 flex-none text-rose" aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <p className="text-[10px] font-semibold uppercase tracking-[0.04em] text-rose">INGEST ENGINE REQUEST FAILED</p>
        <p className="mt-1 break-words font-mono text-[9px] leading-4 text-slate-400">{message}</p>
        {onRetry && (
          <Button variant="ghost" onClick={onRetry} className="mt-2 -ml-2 px-2 py-1 text-rose">
            <RotateCw size={11} aria-hidden="true" /> {retryLabel}
          </Button>
        )}
      </div>
    </div>
  );
}

export function DividerLabel({ children, className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cx('flex items-center gap-2', className)} {...props}>
      <span className="h-px flex-1 bg-border" />
      <span className="font-mono text-[8px] uppercase tracking-[0.08em] text-slate-600">{children}</span>
      <span className="h-px flex-1 bg-border" />
    </div>
  );
}
