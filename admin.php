<?php
class LoginProtectionAdmin extends LoginProtection
{
	protected $capability_required;
	protected $fields;
	protected $form_action;
	protected $page_options;
	protected $text_settings;

	public function __construct()
	{
		$this->initialize();
		$this->set_fields();

		$this->text_settings = _(self::NAME) . ' ' . __('Settings');

		if (is_multisite())
		{
			$this->capability_required = 'manage_network_options';
			$this->form_action = '../options.php';
			$this->page_options = 'settings.php';
		} else {
			$this->capability_required = 'manage_options';
			$this->form_action = 'options.php';
			$this->page_options = 'options-general.php';
		}
	}

	public function activate()
	{
		global $wpdb;

		if (is_multisite() && !is_network_admin()) die($this->h(sprintf(__("%s must be activated via the Network Admin interface when WordPress is in multistie network mode.", self::ID), self::NAME)));

		require_once(ABSPATH . 'wp-admin/includes/upgrade.php');

		$sql = "CREATE TABLE `$this->table_auth_fail` (
				ip VARCHAR(39) NOT NULL DEFAULT '',
				count INT(3) NOT NULL DEFAULT 0,
				blocked DATETIME DEFAULT NULL,
				created DATETIME DEFAULT NULL,
				updated DATETIME DEFAULT NULL,
				PRIMARY KEY  (ip)
				)";

		dbDelta($wpdb->prepare($sql, null));

		if ($wpdb->last_error) die($wpdb->last_error);

		if (is_multisite()) switch_to_blog(1);

		update_option($this->option_name, $this->options);

		if (is_multisite()) restore_current_blog();
	}

	public function deactivate() {
		global $wpdb;

		$prior_error_setting = $wpdb->show_errors;
		$wpdb->show_errors = false;
		$denied = 'command denied to user';

		$wpdb->query($wpdb->prepare("DROP TABLE `$this->table_auth_fail`", null));
		if ($wpdb->last_error) {
			if (strpos($wpdb->last_error, $denied) === false) {
				die($wpdb->last_error);
			}
		}

		$wpdb->show_errors = $prior_error_setting;

		$package_id = self::ID;
		$wpdb->escape_by_ref($package_id);

		$wpdb->query($wpdb->prepare("DELETE FROM `$wpdb->options` WHERE option_name LIKE %s", "$package_id%"));

		$wpdb->query($wpdb->prepare("DELETE FROM `$wpdb->usermeta` WHERE meta_key LIKE %s", "$package_id%"));
	}

	public function plugin_action_links($links)
	{
		$links[] = '<a href="' . $this->h($this->page_options) . '?page=' . self::ID . '">' . $this->h(__('Settings')) . '</a>';
		return $links;
	}

	public function admin_menu()
	{
		add_submenu_page(
			$this->page_options,
			$this->text_settings,
			self::NAME,
			$this->capability_required,
			self::ID,
			array(&$this, 'page_settings')
		);
	}

	public function page_settings()
	{
		if (is_multisite()) include_once ABSPATH . 'wp-admin/options-head.php';

		echo '<div class="wrap">';
		screen_icon('options-general');
		echo '<h2>' . $this->h($this->text_settings) . '</h2>';
		echo '<form action="' . $this->h($this->form_action) . '" method="post">' . "\n";
		settings_fields($this->option_name);
		do_settings_sections(self::ID);
		submit_button();
		echo '</form>';
		echo '</div>';
	}

	public function admin_init()
	{
		register_setting(
			$this->option_name,
			$this->option_name,
			array(&$this, 'validate')
		);

		$this->add_settings_values();

		add_settings_section(
			self::ID . '-block',
			$this->h(__("Login Block", self::ID)),
			array(&$this, 'section_block'),
			self::ID
		);

		add_settings_section(
			self::ID . '-auth',
			$this->h(__("Basic Authentication", self::ID)),
			array(&$this, 'section_auth'),
			self::ID
		);

		foreach ($this->fields as $id => $field)
		{
			add_settings_field(
				$id,
				$this->h($field['label']),
				array(&$this, $id),
				self::ID,
				self::ID . '-' . $field['group']
			);
		}
	}

	public function section_auth()
	{
		echo '<p>';
		echo $this->h(__("Set the Basic Authentication to the login page of the admin pages.", self::ID));
		echo '</p>';
	}

	public function section_block()
	{
		echo '<p>';
		echo $this->h(__("Protect an admin login page from unauthorized access.", self::ID));
		echo '</p>';
	}

	protected function set_fields()
	{
		$this->fields = array(
			'block_login_enable' => array(
				'group' => 'block',
				'label' => __("Block enable", self::ID),
				'text' => __("Block setting of access that fails authentication.", self::ID),
				'type' => 'bool',
				'bool0' => __("Off, block is disabled.", self::ID),
				'bool1' => __("On, block is enabled.", self::ID),
			),
			'block_login_threshold' => array(
				'group' => 'block',
				'label' => __("Block threshold", self::ID),
				'text' => __("Number of times to be blocked If the authentication fails continuously. (Do not block when set to '0'.)", self::ID),
				'type' => 'int',
				'required' => true,
				'validates' => array(
					'min_length' => 1,
					'max_length' => 2,
				),
			),
			'block_login_interval' => array(
				'group' => 'block',
				'label' => __("Block interval", self::ID),
				'text' => __("Seconds of interval to reset the continuous authentication failure count. (Do not reset when set to '0'.)", self::ID),
				'type' => 'int',
				'required' => true,
				'validates' => array(
					'min_length' => 1,
					'max_length' => 5,
				),
			),
			'block_login_time' => array(
				'group' => 'block',
				'label' => __("Block time", self::ID),
				'text' => __("Seconds to block the authentication. (Do not release when set to '0'.)", self::ID),
				'type' => 'int',
				'required' => true,
				'validates' => array(
					'min_length' => 1,
					'max_length' => 5,
				),
			),
			'block_login_ips' => array(
				'group' => 'block',
				'label' => __("Block IP", self::ID),
				'text' => __("Ip address list of blocking. (Separate by newline.)", self::ID),
				'type' => 'text',
			),
			'auth_basic_user' => array(
				'group' => 'auth',
				'label' => __("User", self::ID),
				'text' => __("User of Basic Authentication.", self::ID),
				'type' => 'string',
				'required' => false,
				'validates' => array(
					'alphanumeric' => true,
					'min_length' => 4,
					'max_length' => 32,
				),
			),
			'auth_basic_password' => array(
				'group' => 'auth',
				'label' => __("Password", self::ID),
				'text' => sprintf(__("Password of Basic Authentication. Recommended : [ %s ].", self::ID), $this->password(16)),
				'type' => 'string',
				'required' => false,
				'validates' => array(
					'alphanumeric' => true,
					'password' => true,
					'min_length' => 8,
					'max_length' => 32,
				),
			),
		);
	}

	public function __call($name, $params)
	{
		if (empty($this->fields[$name]['type'])) return;

		switch ($this->fields[$name]['type'])
		{
		case 'bool':
			$this->input_radio($name);
			break;
		case 'int':
			$this->input_int($name);
			break;
		case 'string':
			$this->input_string($name);
			break;
		case 'text':
			$this->input_text($name);
			break;
		}
	}

	protected function input_radio($name)
	{
		echo $this->h($this->fields[$name]['text']);
		echo '<p><label>';
		echo '<input type="radio" value="0" name="'
			. $this->h($this->option_name)
			. '[' . $this->h($name) . ']"'
			. ($this->options[$name] ? '' : ' checked="checked"') . ' /> ';
		echo $this->h($this->fields[$name]['bool0']);
		echo '</p></label>';
		echo '<p><label>';
		echo '<input type="radio" value="1" name="'
			. $this->h($this->option_name)
			. '[' . $this->h($name) . ']"'
			. ($this->options[$name] ? ' checked="checked"' : '') . ' /> ';
		echo $this->h($this->fields[$name]['bool1']);
		echo '</p></label>';
	}

	protected function input_int($name)
	{
		echo '<input type="text" size="3" name="'
			. $this->h($this->option_name)
			. '[' . $this->h($name) . ']"'
			. ' value="' . $this->h($this->options[$name]) . '" /> ';
		echo '<label>'
			. $this->h($this->fields[$name]['text'] . ' ' . __('Default:', self::ID) . ' ' . $this->options_default[$name] . '.')
			. '</label>';
	}

	protected function input_string($name)
	{
		echo '<input type="text" size="75" name="'
			. $this->h($this->option_name)
			. '[' . $this->h($name) . ']"'
			. ' value="' . $this->h($this->options[$name]) . '" /> ';
		echo '<p><label>'
			. $this->h($this->fields[$name]['text'] . ' ' . __('Default:', self::ID) . ' ' . $this->options_default[$name] . '.')
			. '</p></label>';
	}

	protected function input_text($name)
	{
		echo '<p><label>'
			. $this->h($this->fields[$name]['text'] . ' ' . __('Default:', self::ID) . ' ' . $this->options_default[$name] . '.')
			. '</p></label>';
		echo '<textarea rows="10" cols="50" class="large-text code" name="'
			. $this->h($this->option_name)
			. '[' . $this->h($name) . ']">'
			. $this->h($this->options[$name])
			. '</textarea>';
	}

	public function admin_notices_setting_auth()
	{
		if ($this->is_block_enabled()) return;

		echo '<div class="error">';

		echo '<p><strong>';
		echo $this->h(__("Measures of unauthorized access is disabled!", self::ID));
		echo '</strong></p>';

		echo '<p><strong>';
		echo $this->h(__("Please enable block of unauthorized login access.", self::ID));
		echo '</strong></p>';

		echo '<p><strong>';
		echo '<a href="' . $this->h($this->page_options) . '?page=' . self::ID . '">' . $this->h(__('Settings')) . '</a>';
		echo '</strong></p>';

		echo '</div>';
	}

	public function validate($in)
	{
		$out = $this->options_default;
		if ( ! is_array($in))
		{
			add_settings_error(
				$this->option_name,
				$this->h($this->option_name),
				'Input must be an array.');
			return $out;
		}

		foreach ($this->fields as $name => $field)
		{
			if ( ! array_key_exists($name, $in))
			{
				if ( ! empty($field['required'])) $this->validate_require($in, $name, $field);
				continue;
			}

			if ( ! $this->validate_scalar($in, $name, $field)) continue;

			switch ($field['type'])
			{
			case 'bool':
				if ( ! $this->validate_bool($in, $name, $field)) continue 2;
				break;
			case 'int':
				if ( ! $this->validate_int($in, $name, $field)) continue 2;
				$in[$name] = (int) $in[$name];
				break;
			}

			$validates = (isset($field['validates']) && is_array($field['validates'])) ? $field['validates'] : array();
			foreach (array_keys($validates) as $validate)
			{
				if ( ! call_user_func_array(array(&$this, "validate_{$validate}"), array($in, $name, $field))) continue 2;
			}

			$out[$name] = $in[$name];
		}

		$this->update($out);

		unset($out['block_login_ips']);

		return $out;
	}

	private function add_settings_values()
	{
		global $wpdb;

		if (empty($this->options['block_login_time']))
		{
			$sql = "SELECT ip
					FROM `$this->table_auth_fail`
					WHERE `ip` <> %s
						AND `blocked` IS NOT NULL
					ORDER BY `ip` ASC";
			$ip_array = $wpdb->get_col($wpdb->prepare($sql, $this->remote_addr), 0);
		}
		else
		{
			$sql = "SELECT ip
					FROM `$this->table_auth_fail`
					WHERE `ip` <> %s
						AND `blocked` IS NOT NULL
						AND `blocked` >= %s
					ORDER BY `ip` ASC";
			$dst_time = date('Y-m-d H:i:s', time() - $this->options['block_login_time']);
			$ip_array = $wpdb->get_col($wpdb->prepare($sql, $this->remote_addr, $dst_time), 0);
		}
		$this->options['block_login_ips'] = implode("\r\n", $ip_array);
	}

	private function update($data)
	{
		$this->update_auth_fail($data);
		$this->enable();
	}

	private function enable()
	{
		if (is_file($this->enabled_file)) return;
		file_put_contents($this->enabled_file, '');
	}

	private function update_auth_fail($data)
	{
		global $wpdb;

		$sql = "SELECT *
				FROM `$this->table_auth_fail`
				ORDER BY `ip` ASC";

		$ip_array = $wpdb->get_col($wpdb->prepare($sql, null), 0);
		$result_array = $wpdb->get_results($wpdb->prepare($sql, null), ARRAY_A);

		$old_ips = array();
		if ( ! empty($ip_array) && ! empty($result_array)) $old_ips = array_combine($ip_array, $result_array);

		$new_ips = array_unique(explode("\n", str_replace(array(' ', "\r"), '', $data['block_login_ips'])));
		$now = date('Y-m-d H:i:s');

		foreach ($new_ips as $new_ip)
		{
			if (empty($new_ip)) continue;

			if (empty($old_ips[$new_ip]))
			{
				$wpdb->insert(
					$this->table_auth_fail,
					array(
						'ip' => $new_ip,
						'blocked' => $now,
						'created' => $now,
						'updated' => $now,
					),
					array('%s', '%s', '%s', '%s')
				);
			}
			else
			{
				$auth_fail = $old_ips[$new_ip];
				unset($old_ips[$new_ip]);

				if ( ! empty($auth_fail['blocked'])) continue;

				$wpdb->update(
					$this->table_auth_fail,
					array(
						'blocked' => $now,
						'updated' => $now,
					),
					array(
						'ip' => $new_ip
					),
					array('%s', '%s'),
					array('%s')
				);
			}
		}

		foreach ($old_ips as $old_ip)
		{
			if ($old_ip['count'] < $data['block_login_threshold'] && empty($old_ip['blocked'])) continue;
			$sql = "DELETE FROM `$this->table_auth_fail` WHERE `ip` = %s";
			$wpdb->query($wpdb->prepare($sql, $old_ip['ip']));
		}
	}

	private function validate_require($data, $name, $field)
	{
		if (isset($data[$name]) && $data[$name] != '') return true;

		add_settings_error(
			$this->option_name,
			$this->h($name),
			$this->h("'" . $field['label']) . "' is required.");
		return false;
	}

	private function validate_scalar($data, $name, $field)
	{
		if ( ! isset($data[$name]) || $data[$name] == '') return true;
		if (is_scalar($data[$name])) return true;

		add_settings_error(
			$this->option_name,
			$this->h($name),
			$this->h("'" . $field['label']). "' " . __("was not a scalar.", self::ID));
		return false;
	}

	private function validate_bool($data, $name, $field)
	{
		if ( ! isset($data[$name]) || $data[$name] == '') return true;
		if (is_scalar($data[$name])) return true;
		if (in_array($data[$name], array(0, 1))) return true;

		add_settings_error(
			$this->option_name,
			$this->h($name),
			$this->h("'" . $field['label'] . "' " . __("must be '0' or '1'.", self::ID)));
		return false;
	}

	private function validate_int($data, $name, $field)
	{
		if ( ! isset($data[$name]) || $data[$name] == '') return true;
		if (ctype_digit($data[$name])) return true;

		add_settings_error(
			$this->option_name,
			$this->h($name),
			$this->h("'" . $field['label'] . "' " . __("must be an integer.", self::ID)));
		return false;
	}

	private function validate_alphanumeric($data, $name, $field)
	{
		if ( ! isset($data[$name]) || $data[$name] == '') return true;
		if (preg_match('/^[a-z0-9]+$/i', $data[$name])) return true;

		add_settings_error(
			$this->option_name,
			$this->h($name),
			$this->h("'" . $field['label'] . "' " . __("must be alphanumeric.", self::ID)));
		return false;
	}

	private function validate_password($data, $name, $field)
	{
		if ( ! isset($data[$name]) || $data[$name] == '') return true;
		if (preg_match('/[a-z]/', $data[$name]) && preg_match('/[A-Z]/', $data[$name]) && preg_match('/[0-9]/', $data[$name])) return true;

		add_settings_error(
			$this->option_name,
			$this->h($name),
			$this->h("'" . $field['label'] . "' " . __("include one or more of each upper and lower case letters and numbers.", self::ID)));
		return false;
	}

	private function validate_min_length($data, $name, $field)
	{
		if ( ! isset($data[$name]) || $data[$name] == '') return true;
		if ( ! isset($field['validate']['min_length'])) return true;
		if ($field['validate']['min_length'] <= mb_strlen($data[$name])) return true;

		add_settings_error(
			$this->option_name,
			$this->h($name),
			$this->h("'" . $field['label'] . "' " . sprintf(__("at least %s characters.", self::ID), $field['validate']['min_length'])));
		return false;
	}

	private function validate_max_length($data, $name, $field)
	{
		if ( ! isset($data[$name]) || $data[$name] == '') return true;
		if ( ! isset($field['validate']['max_length'])) return true;
		if (mb_strlen($data[$name]) <= $field['validate']['max_length']) return true;

		add_settings_error(
			$this->option_name,
			$this->h($name),
			$this->h("'" . $field['label'] . "' " . sprintf(__("is less than %s characters.", self::ID), $field['validate']['max_length'])));
		return false;
	}

	private function password($length)
	{
		$ret = '';
		$number = range('0', '9');
		$lower = array_flip(range('a', 'z'));
		$upper = array_flip(range('A', 'Z'));
		$chars = array(
			$number,
			$lower,
			$upper,
		);
		$indexes = array_keys($chars);
		$selected = array();

		for ($i = 0; $i < $length; $i++)
		{
			$unselected = array_diff($indexes, $selected);
			if ($length - $i <= count($unselected)) $index = array_rand($unselected);
			else $index = array_rand($indexes);
			if ( ! in_array($index, $selected)) $selected[] = $index;
			$ret .= (string) array_rand($chars[$index]);
		}

		return $ret;
	}
}
