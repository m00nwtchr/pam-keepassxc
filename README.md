# pam-keepassxc
A PAM module for KeePassXC auto-unlocking.

## WARNING: This is a very early (but functional) prototype. There are no guarantees regarding security or compatibility with your setup.

### REQUIREMENTS

Currently, this only works for in-session authentication, IE with session lockers such as `swaylock`.

Suggested configuration:
- Setup autologin,
- Use `swaylock` as a "login screen" on session start with e.g. `exec swaylock`
- Make sure KeePassXC is started on login as well, in any way you choose.

### Configuration

Install the `libpam_keepassxc.so` library to `/usr/lib/security/pam_keepassxc.so`.

Adjust your `/etc/pam.d/swaylock` or equivalent to add the following line, as the very last `auth` entry in the file.
```
auth optional pam_keepassxc.so
```

Create a `$HOME/.config/security/pam_keepassxc.toml` file, with the following contents:
```toml
database_path = "$HOME/<your database path>"
```

### Contributing

This is literally the first time I'm doing anything with PAM, so I'd appreciate it if someone would point out all the terrible mistakes I'm probably making :D
