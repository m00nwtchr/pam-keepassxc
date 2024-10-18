# pam-keepassxc
A PAM module for auto-unlocking KeePassXC.

## ⚠️ WARNING
This is a prototype. There are no guarantees regarding security or compatibility with your setup.

## Installation

1. Install the following components:
   - Copy the `libpam_keepassxc.so` library to `/usr/lib/security/pam_keepassxc.so`.
   - Install the `systemd/keepassxc.service` as a user systemd service.
   - Install the `systemd/org.keepassxc.KeePassXC.MainWindow.service` as a D-Bus service file.
   - Create a systemd service alias (symlink) from `keepassxc.service` to `dbus-org.keepassxc.KeePassXC.MainWindow.service`.
   - Run the command:
     ```bash
     systemctl --user daemon-reload
     ```

   See `aur/PKGBUILD` for an example.

2. Adjust your PAM configuration:
   - Edit your `/etc/pam.d/swaylock` (or equivalent) file and add the following line as the last `auth` entry:
     ```bash
     auth optional pam_keepassxc.so
     ```

   - For login managers such as `greetd`, also add the following line to your `/etc/pam.d/greetd`, right after every other `session` entry:
     ```bash
     session optional pam_keepassxc.so
     ```

## Configuration

Create a configuration file at `$HOME/.config/security/pam_keepassxc.toml` with the following content:
```toml
database_path = "$HOME/<your database path>"
```

## Contributing

This is my first experience working with PAM, so I would appreciate any feedback on potential security issues and other improvements.

## License

The source code in this repository is licensed under the [Mozilla Public License (MPL)](LICENSE). However, due to the inclusion of the GPLv3.0-licensed `pamsm` crate, any resulting compiled binaries are licensed under the GPLv3.0.

If you distribute the compiled binaries, you must comply with the terms of the GPLv3.0.
