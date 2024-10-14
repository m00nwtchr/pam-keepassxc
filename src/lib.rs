use std::{error::Error, fs};

use pamsm::{pam_module, LogLvl, Pam, PamData, PamError, PamFlags, PamLibExt, PamServiceModule};
use serde::Deserialize;
use users::{os::unix::UserExt, User};
use zbus::{blocking::Connection, proxy};

struct PamKeePassXC;

#[derive(Debug, Clone)]
struct SessionData(Option<String>);

const MODULE_NAME: &str = "pam_keepassxc";

#[proxy(
	interface = "org.keepassxc.KeePassXC.MainWindow",
	default_service = "org.keepassxc.KeePassXC.MainWindow",
	default_path = "/keepassxc",
	gen_async = false
)]
trait MainWindow {
	#[zbus(name = "openDatabase")]
	fn open_database(&self, database_path: &str, password: &str) -> zbus::Result<()>;
}

impl PamData for SessionData {
	fn cleanup(&self, _pam: Pam, flags: PamFlags, _status: PamError) {
		if !flags.contains(PamFlags::SILENT) {}
	}
}

fn unlock_keepassxc(database: &str, pass: &str) -> Result<(), Box<dyn Error>> {
	let connection = Connection::session()?;
	let proxy = MainWindowProxy::new(&connection)?;

	Ok(proxy.open_database(database, pass)?)
}

#[derive(Deserialize)]
struct UserConfig {
	database_path: String,
}

fn user_config(user: &User) -> Option<UserConfig> {
	let config_path = user
		.home_dir()
		.join(".config")
		.join("security")
		.join(MODULE_NAME)
		.with_extension("toml");

	toml::de::from_str(&fs::read_to_string(config_path).ok()?).ok()
}

fn database_path(user: &User, config: &UserConfig) -> String {
	let home_dir = user.home_dir().to_str().expect("");

	let mut result = config.database_path.replace("$HOME", home_dir);
	if result.starts_with('~') {
		result.replace_range(0..1, home_dir);
	}
	result = result.replace("//", "/");

	result
}

impl PamServiceModule for PamKeePassXC {
	fn open_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
		let data: SessionData = match unsafe { pamh.retrieve_data(MODULE_NAME) } {
			Err(e) => return e,
			Ok(data) => data,
		};
		let pass = data.0;

		if let Some(pass) = pass {
			pamh.syslog(
				LogLvl::WARNING,
				"Trying to unlock keepassxc on session open...",
			)
			.expect("Failed to send syslog");

			let user = match pamh.get_user(None) {
				Ok(Some(u)) => match users::get_user_by_name(u.to_str().expect("")) {
					Some(u) => u,
					None => return PamError::USER_UNKNOWN,
				},
				Ok(None) => return PamError::USER_UNKNOWN,
				Err(e) => return e,
			};

			let Some(user_config) = user_config(&user) else {
				return PamError::IGNORE;
			};

			if unlock_keepassxc(&database_path(&user, &user_config), &pass).is_err() {
				return PamError::AUTH_ERR;
			}

			let data = SessionData(None);
			if let Err(e) = unsafe { pamh.send_data(MODULE_NAME, data) } {
				return e;
			}
		}

		PamError::SUCCESS
	}

	fn close_session(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
		PamError::IGNORE
	}

	fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
		let user = match pamh.get_user(None) {
			Ok(Some(u)) => match users::get_user_by_name(u.to_str().expect("")) {
				Some(u) => u,
				None => return PamError::USER_UNKNOWN,
			},
			Ok(None) => return PamError::USER_UNKNOWN,
			Err(e) => return e,
		};

		let pass = match pamh.get_authtok(None) {
			Ok(Some(p)) => p,
			Ok(None) => return PamError::AUTH_ERR,
			Err(e) => return e,
		};

		let Some(user_config) = user_config(&user) else {
			return PamError::IGNORE;
		};

		if unlock_keepassxc(
			&database_path(&user, &user_config),
			pass.to_str().expect(""),
		)
		.is_err()
		{
			pamh.syslog(
				LogLvl::WARNING,
				"Unable to unlock keepass on auth, sending password to session",
			)
			.expect("Failed to send syslog");

			let data = SessionData(Some(pass.to_string_lossy().to_string()));
			if let Err(e) = unsafe { pamh.send_data(MODULE_NAME, data) } {
				return e;
			}
			return PamError::AUTH_ERR;
		}

		PamError::SUCCESS
	}
}

pam_module!(PamKeePassXC);
