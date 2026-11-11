import { CircleHelp } from "lucide-react";
import { Tooltip } from "radix-ui";

export function Help({ text }: { text: string }) {
  return <Tooltip.Root delayDuration={200}><Tooltip.Trigger asChild><button className="help-icon" aria-label={text} type="button"><CircleHelp size={14} /></button></Tooltip.Trigger><Tooltip.Portal><Tooltip.Content className="tooltip" sideOffset={7}>{text}</Tooltip.Content></Tooltip.Portal></Tooltip.Root>;
}
