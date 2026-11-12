# ~/.bashrc
alias ll='ls -alF'
[ -f ~/.bash_aliases ] && . ~/.bash_aliases
export PATH="$HOME/.local/bin:$PATH"
eval "$(dircolors -b ~/.dircolors)"
[ -f ~/.fzf.bash ] && source ~/.fzf.bash
