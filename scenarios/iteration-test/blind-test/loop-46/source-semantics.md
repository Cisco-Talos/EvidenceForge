# Native protocol references

Zeek v8.0.5 [DNS handlers](https://github.com/zeek/zeek/blob/v8.0.5/scripts/base/protocols/dns/main.zeek) return the SRV target, MX exchange and SOA primary name. TXT/SPF handlers summarize each wire character-string with its byte length and content. The modeled UTF-8 TXT partition is shared with packet sizing and does not mutate full RDATA consumed by Windows DNS. Long TXT records use multiple at-most255-byte character-strings.

Zeek v8.0.5 [SMB2 handlers](https://github.com/zeek/zeek/blob/v8.0.5/scripts/base/protocols/smb/smb2-main.zeek) populate path and share_type. [SMB1 handlers](https://github.com/zeek/zeek/blob/v8.0.5/scripts/base/protocols/smb/smb1-main.zeek) receive service/native filesystem from the TreeConnectAndX response. The canonical SmbContext explicitly models SMB2/3, not SMB1. Therefore those optional observations are omitted rather than inferred from share names or backing/advertised storage knowledge. Canonical storage facts and already-native raw observations remain supported.

Pinned files were retrieved read-only via the GitHub connector; DNS SHA4ae48baaacc6ee9246b7d9506ec2905f9d4cc866, SMB2 SHA31f0a7704ae94d8f4b48cc0f2491df73a9bd24c7, SMB1 SHA68a5ecbaee670886d26123fc2d31204d7d5afab6.
