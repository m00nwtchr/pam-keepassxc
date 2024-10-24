use std::{
	thread::sleep,
	time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use nix::{sys::socket::UnixAddr, unistd::User};
use rustbus::{
	connection::Timeout,
	wire::{unmarshal::traits::Variant, ObjectPath},
	MessageBuilder, RpcConn, Signature, Unmarshal,
};
use secrecy::{ExposeSecret, SecretString};

use crate::config::{database_path, UserConfig};

const KEEPASSXC_DBUS_NAME: &str = "org.keepassxc.KeePassXC.MainWindow";

const TIMEOUT: Duration = Duration::from_secs(30);
const INTERVAL: Duration = Duration::from_secs(1);

pub fn user_session_bus(user: &User) -> Result<UnixAddr> {
	Ok(UnixAddr::new(
		format!("/run/user/{}/bus", user.uid).as_str(),
	)?)
}

pub fn wait_for_dbus(user: &User) -> Result<RpcConn> {
	let socket_addr = user_session_bus(user)?;

	let start = Instant::now();
	let conn = loop {
		if let Ok(conn) = RpcConn::connect_to_path(socket_addr, Timeout::Duration(TIMEOUT)) {
			break conn;
		}

		if start.elapsed() >= TIMEOUT {
			return Err(anyhow!("Timed out."));
		}
		sleep(INTERVAL);
	};

	Ok(conn)
}

pub fn try_unlock(
	flag: bool,
	user: &User,
	user_config: &UserConfig,
	pass: &SecretString,
) -> Result<()> {
	let mut conn = if flag {
		RpcConn::connect_to_path(user_session_bus(user)?, Timeout::Duration(TIMEOUT))?
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

fn activate(conn: &mut RpcConn) -> Result<()> {
	let mut call = MessageBuilder::new()
		.call("Ping")
		.with_interface("org.freedesktop.DBus.Peer")
		.on("/")
		.at(KEEPASSXC_DBUS_NAME)
		.build();

	let id = conn
		.send_message(&mut call)?
		.write_all()
		.map_err(|err| err.1)?;
	let _ = conn.wait_response(id, Timeout::Duration(TIMEOUT))?;

	Ok(())
}

fn get_pid(conn: &mut RpcConn) -> Result<u32> {
	// Get PID of KeePassXC service.
	let mut call = MessageBuilder::new()
		.call("GetConnectionUnixProcessID")
		.with_interface("org.freedesktop.DBus")
		.on("/")
		.at("org.freedesktop.DBus")
		.build();
	call.body.push_param(KEEPASSXC_DBUS_NAME)?;

	let id = conn.send_message(&mut call)?.write_all().map_err(|e| e.1)?;
	let message = conn.wait_response(id, Timeout::Duration(TIMEOUT))?;

	let pid: u32 = message.body.parser().get()?;
	Ok(pid)
}

fn verify(conn: &mut RpcConn, pid: u32) -> Result<()> {
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
		Err(anyhow!("Invalid keepassxc service"))
	}
}

fn unlock(conn: &mut RpcConn, database: &str, pass: &SecretString) -> Result<()> {
	// Build a D-Bus message to request the unlocking of the KeePassXC database.
	let mut call = MessageBuilder::new()
		.call("openDatabase")
		.with_interface("org.keepassxc.KeePassXC.MainWindow")
		.on("/keepassxc")
		.at(KEEPASSXC_DBUS_NAME)
		.build();
	call.body.push_param2(database, pass.expose_secret())?;

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
