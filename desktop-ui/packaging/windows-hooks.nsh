; The selected scope must not implicitly uninstall or migrate another scope.
!macro EForgeCheckScope
  ${If} $MultiUser.InstallMode == "AllUsers"
    ReadRegStr $0 HKCU "${UNINSTKEY}" "UninstallString"
  ${Else}
    ReadRegStr $0 HKLM "${UNINSTKEY}" "UninstallString"
  ${EndIf}
  ${If} $0 != ""
    MessageBox MB_OK|MB_ICONSTOP "Studio is already installed in the other scope. Uninstall that copy before changing between Just me and Everyone. Your Studio data and workspaces will be preserved." /SD IDOK
    SetErrorLevel 2
    Quit
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro EForgeCheckScope
!macroend
