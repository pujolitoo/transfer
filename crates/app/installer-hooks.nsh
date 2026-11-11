; Registers Transfer to start with Windows and adds it to the Explorer context
; menu. The value name and the marker file match what the app itself uses (see
; enable_autostart_once in src/main.rs).
!define RUN_KEY "Software\Microsoft\Windows\CurrentVersion\Run"
!define APP_DATA_DIR "$APPDATA\com.transfer.desktop"
!define AUTOSTART_MARKER "${APP_DATA_DIR}\autostart.configured"

!define FILE_VERB "Software\Classes\*\shell\Transfer"
!define FOLDER_VERB "Software\Classes\Directory\shell\Transfer"

!macro WriteSendVerb KEY
  WriteRegStr HKCU "${KEY}" "" "Enviar con Transfer"
  WriteRegStr HKCU "${KEY}" "Icon" "$INSTDIR\${MAINBINARYNAME}.exe,0"
  ; The default model hides the entry when more than 15 items are selected.
  WriteRegStr HKCU "${KEY}" "MultiSelectModel" "Player"
  WriteRegStr HKCU "${KEY}\command" "" '"$INSTDIR\${MAINBINARYNAME}.exe" --send "%1"'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro WriteSendVerb "${FILE_VERB}"
  !insertmacro WriteSendVerb "${FOLDER_VERB}"
  Push $0
  ReadRegStr $0 HKCU "${RUN_KEY}" "${PRODUCTNAME}"
  ; A marker with no entry means the user turned autostart off: respect that.
  ; An existing entry is rewritten so it always points at this installation.
  ${If} $0 != ""
  ${OrIfNot} ${FileExists} "${AUTOSTART_MARKER}"
    WriteRegStr HKCU "${RUN_KEY}" "${PRODUCTNAME}" '"$INSTDIR\${MAINBINARYNAME}.exe" --hidden'
    CreateDirectory "${APP_DATA_DIR}"
    FileOpen $0 "${AUTOSTART_MARKER}" w
    FileClose $0
  ${EndIf}
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Updates run the old uninstaller too; those must keep the entry.
  ${If} $UpdateMode <> 1
    DeleteRegValue HKCU "${RUN_KEY}" "${PRODUCTNAME}"
    DeleteRegKey HKCU "${FILE_VERB}"
    DeleteRegKey HKCU "${FOLDER_VERB}"
  ${EndIf}
!macroend
