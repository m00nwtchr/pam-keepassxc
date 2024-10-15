#![warn(clippy::pedantic)]
use std::{
	error::Error,
	fs,
	process::exit,
	thread::sleep,
	time::{Duration, Instant},
};

#[cfg(feature = "session")]
use fork::{close_fd, fork, setsid, waitpid, Fork};
use nix::sys::socket::UnixAddr;
use pamsm::{pam_module, LogLvl, Pam, PamData, PamError, PamFlags, PamLibExt, PamServiceModule};
use rustbus::{MessageBuilder, RpcConn};
use serde::Deserialize;
use users::{
	get_current_gid, get_current_uid,
	os::unix::UserExt,
	switch::{set_both_gid, set_both_uid, set_effective_gid, set_effective_uid},
	User,
};

struct PamKeePassXC;

#[derive(Debug, Clone)]
#[cfg(feature = "session")]
struct SessionData(Option<String>);

const MODULE_NAME: &str = "pam_keepassxc";

impl PamData for SessionData {
	fn cleanup(&self, _pam: Pam, flags: PamFlags, _status: PamError) {
		if !flags.contains(PamFlags::SILENT) {}
	}
}

fn unlock_keepassxc(database: &str, pass: &str) -> Result<(), Box<dyn Error>> {
	let mut conn = RpcConn::connect_to_path(
		UnixAddr::new(format!("/run/user/{}/bus", get_current_uid()).as_str())?,
		rustbus::connection::Timeout::Infinite,
	)?;

	let mut call = MessageBuilder::new()
		.call("openDatabase")
		.with_interface("org.keepassxc.KeePassXC.MainWindow")
		.on("/keepassxc")
		.at("org.keepassxc.KeePassXC.MainWindow")
		.build();
	call.body.push_params(&[database, pass])?;

	let _ = conn.send_message(&mut call)?.write_all();

	Ok(())
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

	basic_toml::from_str(&fs::read_to_string(config_path).ok()?).ok()
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

/**
 * Will only return for the parent & grandchild
**/
#[cfg(feature = "session")]
fn double_fork() -> Result<Fork, i32> {
	match fork() {
		Ok(Fork::Parent(pid)) => {
			let _ = waitpid(pid);

			Ok(Fork::Parent(pid))
		}
		Ok(Fork::Child) => {
			let _ = setsid();
			let _ = close_fd();

			match fork() {
				Ok(Fork::Child) => Ok(Fork::Child),
				_ => exit(0),
			}
		}
		a => a,
	}
}

const TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "session")]
fn wait_for_dbus(user: &User, user_config: &UserConfig, pass: &str) {
	let _ = set_effective_uid(get_current_uid());
	let _ = set_effective_gid(get_current_gid());

	// Set gid first, then uid
	let _ = set_both_gid(user.primary_group_id(), user.primary_group_id());
	let _ = set_both_uid(user.uid(), user.uid());

	let database_path = database_path(user, user_config);
	let start = Instant::now();
	loop {
		if let Ok(()) = unlock_keepassxc(&database_path, pass) {
			break;
		}

		if start.elapsed() >= TIMEOUT {
			break;
		}
		sleep(Duration::from_secs(1));
	}
}

impl PamServiceModule for PamKeePassXC {
	#[cfg(feature = "session")]
	fn open_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
		let data: SessionData = match unsafe { pamh.retrieve_data(MODULE_NAME) } {
			Err(e) => return e,
			Ok(data) => data,
		};
		let pass = data.0;

		if let Some(pass) = pass {
			{
				let data = SessionData(None);
				let _ = unsafe { pamh.send_data(MODULE_NAME, data) };
			}

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

			// Double fork
			match double_fork() {
				Ok(Fork::Parent(pid)) => {
					pamh.syslog(LogLvl::WARNING, &format!("Forked with PID: {pid}"))
						.expect("Failed to send syslog");
				}
				Ok(Fork::Child) => {
					// grandchild
					wait_for_dbus(&user, &user_config, &pass);
					exit(0)
				}
				Err(_) => {}
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
			#[cfg(feature = "session")]
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
			}
			return PamError::AUTH_ERR;
		}

		PamError::SUCCESS
	}

	#[cfg(not(feature = "session"))]
	fn open_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
		return PamError::IGNORE;
	}
}

pam_module!(PamKeePassXC);
