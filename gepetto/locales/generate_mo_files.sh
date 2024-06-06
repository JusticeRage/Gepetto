for PO_FILE in */LC_MESSAGES/*.po
do
    MO_FILE="${PO_FILE/.po/.mo}"
    "C:\Program Files (x86)\GnuWin32\bin\msgfmt.exe" -o "$MO_FILE" "$PO_FILE"
done
