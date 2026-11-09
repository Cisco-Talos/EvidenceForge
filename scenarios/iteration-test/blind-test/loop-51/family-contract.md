# Scheduled-task principal XML

Classification: source_native_single_schema / sibling_defect. The shared Task Scheduler XML builder owns XML representation, not the Windows emitter. TASK_LOGON_SERVICE_ACCOUNT is an API enum, not an XML logonType value. For the three reserved machine accounts, omit the optional LogonType; preserve the UserId and intended run level. Other principals retain Password semantics. Recognize both qualified names and well-known SIDs; do not classify every NT AUTHORITY identity as a service account.

Entry paths: typed task creation, schtasks command parsing, baseline tasks and minimal task-content expansion all reach ActivityGenerator._build_scheduled_task_xml. Consumers: canonical scheduled_task.task_content and Security 4698. Explicit complete raw XML remains caller-owned. Sibling risks: ordinary domain/local users, UPNs, gMSAs, SID principals, service aliases, XML escaping and hourly triggers. No sample host/name/time predicate, no scenario edits.

Primary references: Microsoft principalType schema makes LogonType optional; XML logonType lists only S4U, Password, InteractiveToken and InteractiveTokenOrPassword. MS-TSCH Principal Schema Part distinguishes those XML values from reserved machine principals and TASK_LOGON_TYPE API values.

- https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-principaltype-complextype
- https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-logontype-simpletype
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/b9420a4c-fe40-45a0-ae85-2d57e051409b

Hard invariant: all generated LogonType elements belong to the XML enumeration; reserved machine accounts require no password-bearing XML method. Preserve command, arguments, trigger and actor/principal distinction. Verify generated output as well as central and sibling unit paths.
