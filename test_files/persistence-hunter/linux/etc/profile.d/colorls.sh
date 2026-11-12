# Stock RHEL colorls.sh lines
  for colors in "$HOME/.dir_colors.$TERM" "$HOME/.dircolors.$TERM" \
                "$HOME/.dir_colors" "$HOME/.dircolors"; do
    [ -e "$colors" ] && COLORS="$colors" && break
  done
