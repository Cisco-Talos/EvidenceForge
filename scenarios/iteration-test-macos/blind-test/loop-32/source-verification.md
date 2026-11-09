# Native semantics verification

- RFC1035 section4.2.2 specifies a two-byte length field preceding each DNS message over TCP. The prefix belongs to TCP payload accounting; absent response means no response prefix. UDP framing is unchanged. Source: https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2.2
- Nmap's official TCP connect-scan documentation describes a connect system call and closing without application data. A successful TCP connection is not evidence of an SSH password attempt. Native sshd connection/error/closure evidence may still exist. Source: https://nmap.org/book/scan-methods-connect-scan.html
- The earlier Event4658 ProcessName claim is withdrawn, as recorded in loop22/finding-triage-4658.md. No valid Windows field was removed.
