# pam-keepassxc
A PAM module for KeePassXC auto-unlocking.

## WARNING: This is a very early (but functional) prototype. There are no guarantees regarding security or compatibility with your setup.

### Installation

Install: 
  - `libpam_keepassxc.so` library to `/usr/lib/security/pam_keepassxc.so`.
  - `systemd/keepassxc.service` as a user systemd service.
  - `systemd/org.keepassxc.KeePassXC.MainWindow.service` as a dbus service file.
  -  Create a systemd service alias (symlink) from `keepassxc.service` to `dbus-org.keepassxc.KeePassXC.MainWindow.service`
  - `systemctl --user daemon-reload`

See `aur/PKGBUILD` for an example.

Adjust your `/etc/pam.d/swaylock` or equivalent to add the following line, as the very last `auth` entry in the file.
```
auth optional pam_keepassxc.so
```

For login managers such as `greetd`, do the above *and* also add the following line to your `/etc/pam.d/greetd`, right after every other `session` entry in the file.
```
session optional pam_keepassxc.so
```

### Configuration

Create a `$HOME/.config/security/pam_keepassxc.toml` file, with the following contents:
```toml
database_path = "$HOME/<your database path>"
```

### Contributing

This is literally the first time I'm doing anything with PAM, so I'd appreciate it if someone would point out all the terrible mistakes I'm probably making :D

### License

The source code in this repository is licensed under the [Mozilla Public License (MPL)](LICENSE). However, due to the inclusion of the GPLv3.0-licensed `pamsm` crate, any resulting compiled binaries are licensed under the GPLv3.0.

If you distribute the compiled binaries, you must comply with the terms of the GPLv3.0.
