#![warn(clippy::pedantic)]
use std::{
	fs,
	process::exit,
	thread::sleep,
	time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use log::{error, warn};
use nix::{sys::socket::UnixAddr, unistd::User};
use pamsm::{pam_module, LogLvl, Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use rustbus::{
	connection::Timeout,
	wire::{unmarshal::traits::Variant, ObjectPath},
	MessageBuilder, RpcConn, Signature, Unmarshal,
};
use serde::Deserialize;

const MODULE_NAME: &str = "pam_keepassxc";

struct PamKeePassXC;

#[derive(Deserialize)]
struct UserConfig {
	database_path: String,
}

fn user_config(user: &User) -> Option<UserConfig> {
	let config_path = user
		.dir
		.join(".config")
		.join("security")
		.join(MODULE_NAME)
		.with_extension("toml");

	basic_toml::from_str(&fs::read_to_string(config_path).ok()?).ok()
}

fn database_path(user: &User, config: &UserConfig) -> String {
	let home_dir = user.dir.to_str().expect("");

	let mut result = config.database_path.replace("$HOME", home_dir);
	if result.starts_with('~') {
		result.replace_range(0..1, home_dir);
	}
	result = result.replace("//", "/");

	result
}

use nix::unistd::{fork, ForkResult};

/**
 * Perform a double fork to detach the process and avoid zombie processes.
**/
#[cfg(feature = "session")]
fn double_fork() -> Result<ForkResult> {
	use nix::{
		sys::wait::waitpid,
		unistd::{close, setsid},
	};

	unsafe {
		match fork() {
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
				match fork() {
					Ok(ForkResult::Child) => Ok(ForkResult::Child),
					_ => exit(0),
				}
			}
			Err(err) => Err(anyhow!("{}", err)),
		}
	}
}

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

const KEEPASSXC_OBJECT: &str = "org.keepassxc.KeePassXC.MainWindow";

const TIMEOUT: Duration = Duration::from_secs(30);
const INTERVAL: Duration = Duration::from_secs(1);

fn unlock(conn: &mut RpcConn, database: &str, pass: &str) -> Result<()> {
	// Build a D-Bus message to request the unlocking of the KeePassXC database.
	let mut call = MessageBuilder::new()
		.call("openDatabase")
		.with_interface("org.keepassxc.KeePassXC.MainWindow")
		.on("/keepassxc")
		.at(KEEPASSXC_OBJECT)
		.build();
	call.body.push_param2(database, pass)?;

	let _ = conn.send_message(&mut call)?.write_all();

	Ok(())
}

#[derive(Unmarshal, Signature)]
struct SystemdExec {
	path: String,       // s
	_args: Vec<String>, // as
	_flag: bool,        // b
	_a: u64,            // t
	_b: u64,            // t
	_c: u64,            // t
	_d: u64,            // t
	pid: u32,           // u
	_timestamp: i32,    // i
	_timestamp2: i32,   // i
}

pub fn verify(conn: &mut RpcConn, pid: u32) -> Result<()> {
	let mut call = MessageBuilder::new()
		.call("GetUnitByPID")
		.with_interface("org.freedesktop.systemd1.Manager")
		.on("/org/freedesktop/systemd1")
		.at("org.freedesktop.systemd1")
		.build();
	call.body.push_param(pid)?;

	let id = conn.send_message(&mut call)?.write_all().map_err(|e| e.1)?;
	let reply = conn.wait_response(id, Timeout::Duration(TIMEOUT))?;
	if let Some(err) = reply.dynheader.error_name {
		return Err(anyhow!(err));
	}

	let service_object: ObjectPath<&str> = reply.body.parser().get()?;

	let mut call = MessageBuilder::new()
		.call("Get")
		.with_interface("org.freedesktop.DBus.Properties")
		.on(service_object.as_ref())
		.at("org.freedesktop.systemd1")
		.build();
	call.body
		.push_param2("org.freedesktop.systemd1.Service", "ExecStart")?;

	let id = conn
		.send_message(&mut call)?
		.write_all()
		.map_err(|err| err.1)?;
	let reply = conn.wait_response(id, Timeout::Duration(TIMEOUT))?;

	let exec: Vec<SystemdExec> = reply.body.parser().get::<Variant>()?.get()?;
	let exec = exec.first().ok_or(anyhow!(""))?;

	if exec.path == "/usr/bin/keepassxc" && exec.pid == pid {
		Ok(())
	} else {
		Err(anyhow!("Invalid"))
	}
}

pub fn get_pid(conn: &mut RpcConn) -> Result<u32> {
	// Get PID of KeePassXC service.
	let mut call = MessageBuilder::new()
		.call("GetConnectionUnixProcessID")
		.with_interface("org.freedesktop.DBus")
		.on("/")
		.at("org.freedesktop.DBus")
		.build();
	call.body.push_param(KEEPASSXC_OBJECT)?;

	let id = conn.send_message(&mut call)?.write_all().map_err(|e| e.1)?;
	let message = conn.wait_response(id, Timeout::Duration(TIMEOUT))?;

	let pid: u32 = message.body.parser().get()?;
	Ok(pid)
}

pub fn activate(conn: &mut RpcConn) -> Result<()> {
	let mut call = MessageBuilder::new()
		.call("Ping")
		.with_interface("org.freedesktop.DBus.Peer")
		.on("/")
		.at(KEEPASSXC_OBJECT)
		.build();

	let id = conn
		.send_message(&mut call)?
		.write_all()
		.map_err(|err| err.1)?;
	let _ = conn.wait_response(id, Timeout::Duration(TIMEOUT))?;

	Ok(())
}

pub fn wait_for_dbus(user: &User) -> Result<RpcConn> {
	let socket_addr = UnixAddr::new(format!("/run/user/{}/bus", user.uid).as_str())?;

	let start = Instant::now();
	let conn = loop {
		match RpcConn::connect_to_path(socket_addr, rustbus::connection::Timeout::Infinite) {
			Ok(conn) => break conn,
			Err(_) => {
				if start.elapsed() >= TIMEOUT {
					return Err(anyhow!("Timed out."));
				}
				sleep(INTERVAL)
			}
		}
	};

	Ok(conn)
}

fn try_unlock(flag: bool, user: &User, user_config: &UserConfig, pass: &str) -> Result<()> {
	let mut conn = if flag {
		let socket_addr = UnixAddr::new(format!("/run/user/{}/bus", user.uid).as_str())?;

		RpcConn::connect_to_path(socket_addr, rustbus::connection::Timeout::Infinite)?
	} else {
		wait_for_dbus(user)?
	};

	activate(&mut conn)?;

	let pid = get_pid(&mut conn)?;
	verify(&mut conn, pid)?;

	let database_path = database_path(user, user_config);
	unlock(&mut conn, &database_path, pass)?;
	Ok(())
}

#[cfg(feature = "session")]
fn grandchild(user: &User, user_config: &UserConfig, pass: &str) -> Result<()> {
	use nix::unistd::{getgid, getuid, setgid, setresgid, setresuid, setuid};

	let _ = setuid(getuid());
	let _ = setgid(getgid());

	let _ = setresgid(user.gid, user.gid, user.gid);
	let _ = setresuid(user.uid, user.uid, user.uid);

	try_unlock(false, user, user_config, pass)?;
	Ok(())
}

impl PamServiceModule for PamKeePassXC {
	#[cfg(feature = "session")]
	fn open_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
		let _ = init_syslog();
		let data = match pamh.retrieve_bytes(MODULE_NAME) {
			Err(e) => return e,
			Ok(data) => data,
		};
		let pass = String::from_utf8_lossy(&data);
		let _ = pamh.send_bytes(MODULE_NAME, Vec::new(), None); // Clear saved password

		pamh.syslog(
			LogLvl::WARNING,
			"Trying to unlock keepassxc on session open...",
		)
		.expect("Failed to send syslog");

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
				pamh.syslog(LogLvl::WARNING, &format!("Forked with PID: {child}"))
					.expect("Failed to send syslog");
			}
			Ok(ForkResult::Child) => {
				// Grandchild process that waits for the D-Bus service to be ready.
				let _ = grandchild(&user, &user_config, &pass);
				exit(0)
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
			Ok(Some(p)) => p.to_str().expect(""),
			Ok(None) => return PamError::AUTH_ERR,
			Err(e) => return e,
		};

		let Some(user_config) = user_config(&user) else {
			return PamError::IGNORE;
		};

		if let Err(err) = try_unlock(true, &user, &user_config, pass) {
			error!("{}", err);
			#[cfg(feature = "session")]
			{
				warn!("Unable to unlock keepass on auth, sending password to session");

				if let Err(e) = pamh.send_bytes(MODULE_NAME, pass.as_bytes().to_vec(), None) {
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
