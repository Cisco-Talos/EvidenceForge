import { Fragment, useRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { MoreHorizontal, Trash2 } from "lucide-react";
import { DropdownMenu } from "radix-ui";
import { ConfirmModal } from "./Modal";

/** Menu sections, in display order: open/view, task actions, manage, locate, organize, remove. */
export type ActionGroup = "inspect" | "work" | "manage" | "locate" | "organize" | "remove";

export interface ObjectAction {
  id: string;
  label: string;
  group: ActionGroup;
  run?: () => void | Promise<void>;
  disabled?: boolean;
  reason?: string;
  description?: string;
  children?: ObjectAction[];
}

const groups: ActionGroup[] = ["inspect", "work", "manage", "locate", "organize", "remove"];

function ActionLabel({ action }: { action: ObjectAction }) {
  return <>{action.group === "remove" && <Trash2 size={15} aria-hidden="true" />}<span className="object-action-copy"><span>{action.label}</span>{(action.disabled ? action.reason : action.description) && <small>{action.disabled ? action.reason : action.description}</small>}</span></>;
}

function ActionItems({ actions, onChoose }: { actions: ObjectAction[]; onChoose: (action: ObjectAction) => void }) {
  return <>{groups.map((group) => actions.filter((action) => action.group === group)).filter((entries) => entries.length).map((entries, index) => <Fragment key={entries[0].group}>
    {index > 0 && <DropdownMenu.Separator />}
    {entries.map((action) => action.children ? <DropdownMenu.Sub key={action.id}><DropdownMenu.SubTrigger onPointerLeave={(event) => event.preventDefault()} className="object-action-item" disabled={action.disabled} aria-label={action.label} title={action.disabled ? action.reason : action.description}><ActionLabel action={action} /><span aria-hidden="true">›</span></DropdownMenu.SubTrigger><DropdownMenu.Portal><DropdownMenu.SubContent className="conversation-menu object-action-menu" sideOffset={5}><ActionItems actions={action.children} onChoose={onChoose} /></DropdownMenu.SubContent></DropdownMenu.Portal></DropdownMenu.Sub> : <DropdownMenu.Item key={action.id} className={`object-action-item ${action.group === "remove" ? "object-action-removal" : ""}`} disabled={action.disabled} aria-label={action.label} title={action.disabled ? action.reason : action.description} onSelect={() => { if (!action.disabled) onChoose(action); }}><ActionLabel action={action} /></DropdownMenu.Item>)}
  </Fragment>)}</>;
}

/** All object menus use the same groups, labels and removal treatment. */
export function ObjectMenu({ label, actions, className = "", onOpenChange }: {
  label: string; actions: ObjectAction[]; className?: string; onOpenChange?: (open: boolean) => void;
}) {
  const trigger = useRef<HTMLButtonElement>(null);
  const selected = useRef<ObjectAction | null>(null);
  return <DropdownMenu.Root onOpenChange={onOpenChange}><DropdownMenu.Trigger ref={trigger} type="button" className={`icon-button object-menu-trigger ${className}`} aria-label={label} title="More actions" onClick={(event) => event.stopPropagation()} onKeyDown={(event) => event.stopPropagation()}><MoreHorizontal size={17} /></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="conversation-menu object-action-menu" sideOffset={5} align="end" onCloseAutoFocus={(event) => {
    // Finish closing the menu before opening dialogs or moving focus to another row.
    const action = selected.current;
    selected.current = null;
    if (action) { event.preventDefault(); trigger.current?.focus(); void action.run?.(); }
  }} onClick={(event) => event.stopPropagation()} onKeyDown={(event) => event.stopPropagation()}><ActionItems actions={actions} onChoose={(action) => { selected.current = action; }} /></DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>;
}

/** A text shortcut invokes its menu action and uses the same availability. */
export function ActionShortcut({ action, primary = false, className = "", ariaLabel }: {
  action: ObjectAction; primary?: boolean; className?: string; ariaLabel?: string;
}) {
  return <button type="button" aria-label={ariaLabel} className={`${primary ? "button-primary" : "button-quiet"} ${className} ${action.group === "remove" ? "removal-shortcut" : ""}`} disabled={action.disabled} title={action.disabled ? action.reason : action.description} onClick={(event) => { event.stopPropagation(); if (!action.disabled) void action.run?.(); }}>{action.group === "remove" && <Trash2 size={15} aria-hidden="true" />}{action.label}</button>;
}

export function RemovalButton({ children, className = "", ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button type="button" className={`button-danger ${className}`} {...props}><Trash2 size={15} aria-hidden="true" />{children}</button>;
}

/** Removal always explains its concrete consequences before invoking the action. */
export function RemovalConfirmation({ title, children, label, busy = false, onCancel, onConfirm }: {
  title: string; children: ReactNode; label: string; busy?: boolean;
  onCancel: () => void; onConfirm: () => void | Promise<void>;
}) {
  return <ConfirmModal title={title} confirmLabel={label} busy={busy} onCancel={onCancel} onConfirm={onConfirm}>{children}</ConfirmModal>;
}
