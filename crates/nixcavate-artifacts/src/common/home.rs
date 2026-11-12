//! The user a file belongs to, read from its home-directory path. Shared by the shell and
//! tool history parsers.

/// `home/alice/..` and `Users/alice/..` give `alice`; `root/..`, `var/root/..` and
/// `private/var/root/..` give `root`; anything else gives an empty string.
pub fn user_from_path(path: &str) -> &str {
    let path = path.trim_start_matches('/');
    if ["root/", "var/root/", "private/var/root/"].iter().any(|prefix| path.starts_with(prefix)) {
        return "root";
    }
    for prefix in ["home/", "Users/"] {
        if let Some((user, _)) = path.strip_prefix(prefix).and_then(|rest| rest.split_once('/')) {
            return user;
        }
    }
    ""
}

#[cfg(test)]
mod tests {
    use super::user_from_path;

    #[test]
    fn users_from_home_layouts() {
        assert_eq!(user_from_path("home/alice/.bash_history"), "alice");
        assert_eq!(user_from_path("Users/sam/.zsh_history"), "sam");
        assert_eq!(user_from_path("root/.viminfo"), "root");
        assert_eq!(user_from_path("var/root/.zsh_history"), "root");
        assert_eq!(user_from_path("private/var/root/.zsh_history"), "root");
        assert_eq!(user_from_path("etc/passwd"), "");
        assert_eq!(user_from_path("home/alice"), "");
    }
}
