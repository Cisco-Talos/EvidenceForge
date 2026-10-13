import { memo, useRef } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeHighlight from "rehype-highlight";
import { ChatCopyButton } from "./ChatCopyButton";

function CodeBlock({ children }: { children?: React.ReactNode }) {
  const node = useRef<HTMLPreElement>(null);
  return <div className="chat-code-block"><ChatCopyButton label="Copy code" text={() => node.current?.querySelector("code")?.textContent || ""} /><pre ref={node}>{children}</pre></div>;
}

/** Render model-authored Markdown without executing embedded HTML. */
export const ChatMarkdown = memo(function ChatMarkdown({ text }: { text: string }) {
  return <div className="chat-markdown"><Markdown
    skipHtml
    remarkPlugins={[remarkGfm]}
    rehypePlugins={[[rehypeHighlight, { detect: false, ignoreMissing: true }]]}
    components={{
      a: ({ children, href }) => href && /^(https?:|mailto:)/i.test(href)
        ? <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>
        : <span title={href}>{children}</span>,
      img: ({ alt }) => <span>{alt ? `[Image: ${alt}]` : "[Image]"}</span>,
      pre: ({ children }) => <CodeBlock>{children}</CodeBlock>,
      table: ({ children }) => <div className="chat-table-scroll"><table>{children}</table></div>,
    }}
  >{text}</Markdown></div>;
});
