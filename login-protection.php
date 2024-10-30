<?php
/*
Plugin Name: Login Protection
Plugin URI: http://wordpress.org/plugins/login-protection/
Description: This plugin make improve the security of the administration page by taking advantage of such as basic authentication.
Author: couhie
Version: 0.2.5
Author URI:
License: GPLv2
Text Domain: login-protection
Domain Path: /languages
*/
$GLOBALS['login_protection'] = new LoginProtection;

class LoginProtection
{
	const ID = 'login-protection';
	const NAME = 'Login Protection';
	const VERSION = '0.1.0';

	protected $prefix = 'login_protection_';
	protected $remote_addr = '';
	protected $cache_dir = '';
	protected $enabled_file = '';
	protected $loaded_textdomain = false;
	protected $option_name;
	protected $options = array();
	protected $options_default = array(
		'block_login_enable' => 0,
		'block_login_threshold' => 10,
		'block_login_interval' => 3600,
		'block_login_time' => 3600,
		'auth_basic_user' => '',
		'auth_basic_password' => '',
	);

	public function __construct()
	{
		$this->initialize();

		add_action('login_init', array(&$this, 'login_init'));

		if (is_admin())
		{
			$this->load_plugin_textdomain();

			require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'admin.php');
			$admin = new LoginProtectionAdmin;

			if (is_multisite())
			{
				$admin_menu = 'network_admin_menu';
				$admin_notices = 'network_admin_notices';
				$plugin_action_links = 'network_admin_plugin_action_links_login-protection/login-protection.php';
			}
			else
			{
				$admin_menu = 'admin_menu';
				$admin_notices = 'admin_notices';
				$plugin_action_links = 'plugin_action_links_login-protection/login-protection.php';
			}

			add_action($admin_menu, array(&$admin, 'admin_menu'));
			add_action('admin_init', array(&$admin, 'admin_init'));
			add_filter($plugin_action_links, array(&$admin, 'plugin_action_links'));

			register_activation_hook(__FILE__, array(&$admin, 'activate'));
			register_deactivation_hook(__FILE__, array(&$admin, 'deactivate'));

			add_action($admin_notices, array(&$admin, 'admin_notices_setting_auth'));
		}
	}

	protected function initialize()
	{
		global $wpdb;

		if ( ! empty($_SERVER['REMOTE_ADDR'])) $this->remote_addr = $_SERVER['REMOTE_ADDR'];

		$this->cache_dir = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'cache' .DIRECTORY_SEPARATOR;
		if ( ! is_dir($this->cache_dir)) mkdir($this->cache_dir);
		$this->enabled_file = $this->cache_dir . 'enabled';

		$this->table_auth_fail = $wpdb->get_blog_prefix(0) . $this->prefix . 'auth_fail';
		$this->option_name = self::ID . '-options';

		$this->set_options();
	}

	protected function h($in)
	{
		return htmlspecialchars($in, ENT_QUOTES, 'UTF-8');
	}

	protected function block($message)
	{
		header('HTTP/1.1 403 Forbidden');
		die($this->h($message));
	}

	protected function load_plugin_textdomain()
	{
		if ( ! $this->loaded_textdomain)
		{
			load_plugin_textdomain(self::ID, false, self::ID . '/languages');
			$this->loaded_textdomain = true;
		}
	}

	protected function set_options()
	{
		if (is_multisite())
		{
			switch_to_blog(1);
			$options = get_option($this->option_name);
			restore_current_blog();
		} else {
			$options = get_option($this->option_name);
		}
		if ( ! is_array($options)) {
			$options = array();
		}
		$this->options = array_merge($this->options_default, $options);
	}

	protected function is_enabled()
	{
		if ( ! is_file($this->enabled_file)) return false;
		return true;
	}

	protected function is_block_enabled()
	{
		if ( ! $this->is_enabled()) return false;
		if (empty($this->options['block_login_enable'])) return false;
		return true;
	}

	protected function is_auth_enabled()
	{
		if ( ! $this->is_enabled()) return false;
		if (empty($this->options['auth_basic_user']) || empty($this->options['auth_basic_password'])) return false;
		return true;
	}

	protected function is_blocked($data)
	{
		if (empty($data['blocked'])) return false;
		if (empty($this->options['block_login_time'])) return true;
		if (strtotime($data['blocked']) + $this->options['block_login_time'] < time())
		{
			$this->clear_auth_fail();
			return false;
		}
		return true;
	}

	public function login_init()
	{
		if ( ! $this->is_enabled()) return;

		nocache_headers();

		$this->validate_auth();
		$this->validate_block();
	}

	private function validate_auth()
	{
		if ( ! $this->is_auth_enabled()) return;

		$user = isset($_SERVER["PHP_AUTH_USER"]) ? $_SERVER["PHP_AUTH_USER"] : '';
		$password  = isset($_SERVER["PHP_AUTH_PW"])   ? $_SERVER["PHP_AUTH_PW"]   : '';

		if ($this->options['auth_basic_user'] == $user && $this->options['auth_basic_password'] == $password) return;

		header('WWW-Authenticate: Basic realm="Please Enter Your Password"');
		header('HTTP/1.0 401 Unauthorized');

		die(__('Authorization Required.'));
	}

	private function validate_block()
	{
		if ( ! $this->is_block_enabled()) return;

		global $wpdb;

		if (empty($this->remote_addr)) $this->block(__('Your remote addr is empty!'));

		$sql = "SELECT count, blocked, updated FROM `$this->table_auth_fail` WHERE `ip` = %s";

		$result = $wpdb->get_row($wpdb->prepare($sql, $this->remote_addr), ARRAY_A);
		$count = empty($result['count']) ? 0 : $result['count'];

		if ($this->is_blocked($result)) $this->block(sprintf(__('Has been blocked. [%s]'), $this->remote_addr));

		$this->reset_auth_fail($result);

		$user = isset($_POST['log']) ? $_POST['log'] : '';
		$password = isset($_POST['pwd']) ? $_POST['pwd'] : '';
		if ($user == '' && $password == '') return;

		if ( ! is_wp_error(wp_authenticate($user, $password)))
		{
			$this->clear_auth_fail();
			return;
		}

		$count = $this->incr_auth_fail($count);

		if (empty($this->options['block_login_threshold'])) return;

		if ($this->options['block_login_threshold'] <= $count)
		{
			$this->block_auth_fail();
			$this->block(sprintf(__('Has been blocked. [%s]'), $this->remote_addr));
		}
	}

	private function incr_auth_fail($count)
	{
		if (empty($this->remote_addr)) return 0;

		global $wpdb;

		$count++;
		$now = date('Y-m-d H:i:s');

		if ($count == 1)
		{
			$wpdb->insert(
				$this->table_auth_fail,
				array(
					'ip' => $this->remote_addr,
					'count' => $count,
					'created' => $now,
					'updated' => $now,
				),
				array('%s', '%d', '%s', '%s')
			);
		}
		else
		{
			$wpdb->update(
				$this->table_auth_fail,
				array(
					'count' => $count,
					'updated' => $now,
				),
				array(
					'ip' => $this->remote_addr
				),
				array('%d', '%s'),
				array('%s')
			);
		}

		return $count;
	}

	private function block_auth_fail()
	{
		if (empty($this->remote_addr)) return false;

		global $wpdb;

		$wpdb->update(
			$this->table_auth_fail,
			array(
				'blocked' => date('Y-m-d H:i:s'),
			),
			array(
				'ip' => $this->remote_addr),
			array('%s'),
			array('%s')
		);

		return true;
	}

	private function reset_auth_fail($data)
	{
		if (empty($this->options['block_login_interval'])) return;
		if (empty($data['updated'])) return;
		if (time() <= strtotime($data['updated']) + $this->options['block_login_interval']) return;
		$this->clear_auth_fail();
	}

	private function clear_auth_fail()
	{
		if (empty($this->remote_addr)) return false;

		global $wpdb;

		$sql = "DELETE FROM `$this->table_auth_fail` WHERE `ip` = %s";
		$wpdb->query($wpdb->prepare($sql, $this->remote_addr));

		return true;
	}
}
