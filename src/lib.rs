#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
use anyhow::{anyhow, Result};
use log::{error, warn};
use nix::unistd::User;
use pamsm::{pam_module, Pam, PamData, PamError, PamFlags, PamLibExt, PamServiceModule};
use secrecy::SecretString;

mod config;
mod dbus;

use config::{user_config, UserConfig};
use dbus::try_unlock;

const MODULE_NAME: &str = "pam_keepassxc";

struct PamKeePassXC;

/**
 * Perform a double fork to detach the process and avoid zombie processes.
**/
#[cfg(feature = "session")]
fn double_fork() -> Result<nix::unistd::ForkResult> {
	use nix::{
		sys::wait::waitpid,
		unistd::{close, fork, setsid, ForkResult},
	};
	match unsafe { fork() } {
		Ok(ForkResult::Parent { child, .. }) => {
			let _ = waitpid(child, None); // Wait for the first child process to exit.

			Ok(ForkResult::Parent { child })
		}
		Ok(ForkResult::Child) => {
			let _ = setsid();

			let _ = close(0);
			let _ = close(1);
			let _ = close(2);

			// Fork again to create the grandchild process.
			match unsafe { fork() } {
				Ok(ForkResult::Child) => Ok(ForkResult::Child),
				_ => std::process::exit(0),
			}
		}
		Err(err) => Err(anyhow!("{}", err)),
	}
}

#[cfg(feature = "session")]
fn grandchild(user: &User, user_config: &UserConfig, pass: &SecretString) -> Result<()> {
	use nix::unistd::{getgid, getuid, setgid, setresgid, setresuid, setuid};

	let _ = init_syslog(); // Reinitialize syslog for new PID

	let _ = setuid(getuid());
	let _ = setgid(getgid());

	let _ = setresgid(user.gid, user.gid, user.gid);
	let _ = setresuid(user.uid, user.uid, user.uid);

	try_unlock(false, user, user_config, pass)?;
	Ok(())
}

#[derive(Clone)]
struct SessionData {
	pass: Option<SecretString>, // Secret wrapper ensures data is zeroed on drop.
}

impl PamData for SessionData {}

fn init_syslog() -> Result<()> {
	use log::LevelFilter;
	use syslog::{BasicLogger, Facility, Formatter3164};

	let formatter = Formatter3164 {
		facility: Facility::LOG_USER,
		hostname: None,
		process: MODULE_NAME.into(),
		pid: std::process::id(),
	};

	let logger = syslog::unix(formatter)?;
	log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
		.map(|()| log::set_max_level(LevelFilter::Info))?;

	Ok(())
}

impl PamServiceModule for PamKeePassXC {
	#[cfg(feature = "session")]
	fn open_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
		use nix::unistd::ForkResult;

		let _ = init_syslog();
		let data: SessionData = match unsafe { pamh.retrieve_data(MODULE_NAME) } {
			Err(e) => return e,
			Ok(data) => data,
		};
		let _ = unsafe { pamh.send_data(MODULE_NAME, SessionData { pass: None }) }; // Clear saved data

		let Some(pass) = data.pass else {
			return PamError::SESSION_ERR;
		};

		warn!("Trying to unlock keepassxc on session open...",);
		let user = match pamh.get_user(None) {
			Ok(Some(u)) => match User::from_name(u.to_str().expect("")) {
				Ok(Some(u)) => u,
				_ => return PamError::USER_UNKNOWN,
			},
			Ok(None) => return PamError::USER_UNKNOWN,
			Err(e) => return e,
		};

		let Some(user_config) = user_config(&user) else {
			return PamError::IGNORE;
		};

		match double_fork() {
			Ok(ForkResult::Parent { child, .. }) => {
				warn!("Forked with PID: {child}");
			}
			Ok(ForkResult::Child) => {
				// Grandchild process that waits for the D-Bus service to be ready.
				let _ = grandchild(&user, &user_config, &pass);
				std::process::exit(0)
			}
			Err(_) => {}
		}

		PamError::SUCCESS
	}

	fn close_session(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
		PamError::IGNORE
	}

	fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
		let _ = init_syslog();
		let user = match pamh.get_user(None) {
			Ok(Some(u)) => match User::from_name(u.to_str().expect("")) {
				Ok(Some(u)) => u,
				_ => return PamError::USER_UNKNOWN,
			},
			Ok(None) => return PamError::USER_UNKNOWN,
			Err(e) => return e,
		};

		let pass = match pamh.get_authtok(None) {
			Ok(Some(p)) => SecretString::from(p.to_str().expect("")),
			Ok(None) => return PamError::AUTH_ERR,
			Err(e) => return e,
		};

		let Some(user_config) = user_config(&user) else {
			return PamError::IGNORE;
		};

		if let Err(err) = try_unlock(true, &user, &user_config, &pass) {
			error!("{}", err);
			#[cfg(feature = "session")]
			{
				warn!("Unable to unlock keepass on auth, sending password to session");

				if let Err(e) =
					unsafe { pamh.send_data(MODULE_NAME, SessionData { pass: Some(pass) }) }
				{
					return e;
				}
			}
			return PamError::AUTH_ERR;
		}

		PamError::SUCCESS
	}

	#[cfg(not(feature = "session"))]
	fn open_session(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
		return PamError::IGNORE;
	}
}

pam_module!(PamKeePassXC);
