use std::fs;

use nix::unistd::User;
use serde::Deserialize;

use crate::MODULE_NAME;

#[derive(Deserialize)]
pub struct UserConfig {
	database_path: String,
}

pub fn user_config(user: &User) -> Option<UserConfig> {
	let config_path = user
		.dir
		.join(".config")
		.join("security")
		.join(MODULE_NAME)
		.with_extension("toml");

	basic_toml::from_str(&fs::read_to_string(config_path).ok()?).ok()
}

pub fn database_path(user: &User, config: &UserConfig) -> String {
	let home_dir = user.dir.to_str().expect("");

	let mut result = config.database_path.replace("$HOME", home_dir);
	if result.starts_with('~') {
		result.replace_range(0..1, home_dir);
	}
	result = result.replace("//", "/");

	result
}
