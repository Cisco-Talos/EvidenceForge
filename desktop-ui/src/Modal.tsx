import type { FormEvent, ReactNode } from "react";
import { Trash2 } from "lucide-react";
import { Dialog } from "radix-ui";

export type ModalSize = "sm" | "md" | "lg" | "xl" | "full";
/** `form` collects input, `confirm` asks for one decision, `review` shows what an action affects. */
export type ModalVariant = "form" | "confirm" | "review";

export interface ModalProps {
  /** Visible heading; also the accessible name unless `ariaLabel` is given. */
  title: ReactNode;
  ariaLabel?: string;
  /** One short sentence; longer guidance belongs in docs. */
  description?: ReactNode;
  children?: ReactNode;
  /** Footer buttons, primary action last. */
  actions?: ReactNode;
  onClose: () => void;
  /** While busy, Esc and Cancel cannot dismiss the dialog. */
  busy?: boolean;
  size?: ModalSize;
  variant?: ModalVariant;
  /** Destructive confirm/review dialogs show a removal icon. */
  danger?: boolean;
  /** Wrap the body in a form so Enter submits; the handler receives the prevented event. */
  onSubmit?: (event: FormEvent<HTMLFormElement>) => void;
  className?: string;
  /** Keep the title for assistive technology but do not draw it (for custom headers). */
  hideTitle?: boolean;
  /** Close when the pointer goes down outside. Off by default so input is never lost. */
  dismissOnOutside?: boolean;
  onOpenAutoFocus?: (event: Event) => void;
  onCloseAutoFocus?: (event: Event) => void;
}

/** The one Studio dialog: a Radix dialog with consistent focus, dismissal, layout and actions. */
export function Modal({ title, ariaLabel, description, children, actions, onClose, busy = false, size = "md", variant = "form", danger = false, onSubmit, className = "", hideTitle = false, dismissOnOutside = false, onOpenAutoFocus, onCloseAutoFocus }: ModalProps) {
  const body = <>
    <header className={`modal-header ${hideTitle ? "sr-only" : ""}`}>
      {danger && <span className="modal-danger-icon" aria-hidden="true"><Trash2 size={16} /></span>}
      <div>{hideTitle ? <Dialog.Title asChild><span>{title}</span></Dialog.Title> : <Dialog.Title className="modal-title">{title}</Dialog.Title>}{description && <Dialog.Description className="modal-description">{description}</Dialog.Description>}</div>
    </header>
    {children}
    {actions && <div className="modal-actions">{actions}</div>}
  </>;
  return <Dialog.Root open onOpenChange={(open) => { if (!open && !busy) onClose(); }}><Dialog.Portal>
    <Dialog.Overlay className="modal-overlay" />
    <Dialog.Content className={`modal modal-${size} modal-${variant} ${className}`} {...(ariaLabel ? { "aria-label": ariaLabel, "aria-labelledby": undefined } : {})} {...(description ? {} : { "aria-describedby": undefined })}
      onEscapeKeyDown={(event) => { if (busy) event.preventDefault(); }}
      onPointerDownOutside={(event) => { if (busy || !dismissOnOutside) event.preventDefault(); }}
      onInteractOutside={(event) => { if (busy || !dismissOnOutside) event.preventDefault(); }}
      onOpenAutoFocus={onOpenAutoFocus} onCloseAutoFocus={onCloseAutoFocus}>
      {onSubmit ? <form className="modal-form" onSubmit={(event) => { event.preventDefault(); onSubmit(event); }}>{body}</form> : body}
    </Dialog.Content>
  </Dialog.Portal></Dialog.Root>;
}

/** A single yes/no decision. Destructive by default; the confirm button names the action. */
export function ConfirmModal({ title, ariaLabel, description, children, confirmLabel, onConfirm, onCancel, busy = false, danger = true, confirmDisabled = false }: {
  title: ReactNode; ariaLabel?: string; description?: ReactNode; children?: ReactNode; confirmLabel: string;
  onConfirm: () => void | Promise<void>; onCancel: () => void; busy?: boolean; danger?: boolean; confirmDisabled?: boolean;
}) {
  return <Modal title={title} ariaLabel={ariaLabel} description={description} variant="confirm" size="sm" danger={danger} busy={busy} onClose={onCancel}
    actions={<><button type="button" className="button-quiet" disabled={busy} onClick={onCancel}>Cancel</button>
      <button type="button" className={danger ? "button-danger" : "button-primary"} disabled={busy || confirmDisabled} onClick={() => void onConfirm()}>{danger && <Trash2 size={15} aria-hidden="true" />}{confirmLabel}</button></>}>
    {children}
  </Modal>;
}
