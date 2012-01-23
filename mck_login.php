<?php 

/**
 * Handles site-wide logins, sessions and self-registering
 *
 * @package mck_login
 * @author Casalegno Marco <http://www.kreatore.it/>
 * @author Jukka Svahn <http://rahforum.biz>
 * @license GNU GPLv2
 * @link http://www.kreatore.it/txp/mck_login
 * @link https://github.com/gocom/mck_login
 *
 * Requires Textpattern v4.4.1 (or newer) and PHP v5.2 (or newer)
 */

	if(@txpinterface == 'admin') {
		register_callback(array('mck_login', 'uninstall'), 'plugin_lifecycle.mck_login', 'deleted');
	}
	else {
		register_callback(array('mck_login', 'handler'), 'textpattern');
	}

/**
 * Handles form validation and saving, all of the non-tag stuff
 */

class mck_login {

	static public $form_errors = array();
	static public $action;

	/**
	 * Uninstalls the plugin
	 * @return nothing
	 * @access private
	 */

	static public function uninstall() {
		safe_delete('txp_lang', "name LIKE 'mck\_login\_'");
	}
	
	/**
	 * Add and get form validation errors
	 * @param string $message Either l10n string, or single line of text
	 * @param string $type For which form the error is for.
	 * @return array
	 * <code>
	 *		mck_login::error('abc_l10n_string');
	 * </code>
	 */
	
	static public function error($message=NULL, $type=NULL) {
		
		if(!$type)
			$type = self::$action;
		
		if(!isset(self::$form_errors[$type]))
			self::$form_errors[$type] = array();
		
		if($message !== NULL)
			self::$form_errors[$type][] = $message;
		
		return self::$form_errors[$type];
	}

	/**
	 * Validates login details and handles sessions
	 * @return nothing
	 * @see txp_validate(), generate_password(), $sitename
	 * @access private
	 */

	static public function handler() {

		global $sitename;
	
		extract(doArray(array(
			'name' => ps('mck_login_name'),
			'pass' => ps('mck_login_pass'),
			'stay' => ps('mck_login_stay'),
			'form' => ps('mck_login_form'),
			'reset' => ps('mck_reset'),
			'logout' => gps('mck_logout'),
		), 'trim'));
		
		if(!$form && !$reset && !$logout)
			return;
		
		$is_logged_in = is_logged_in();
		
		if(!defined('mck_login_pub_path'))
			define('mck_login_pub_path', preg_replace('|//$|','/', rhu.'/'));
		
		if(!defined('mck_login_admin_path'))
			define('mck_login_admin_path', '/textpattern/');
		
		if(!defined('mck_login_admin_domain'))
			define('mck_login_admin_domain', '');
		
		/*
			Confirm password reset request
		*/
		
		if($reset && !$form && !$is_logged_in) {
			
			self::$action = 'reset';
			
			callback_event('mck_login.reset_confirm');
			
			sleep(3);

			$confirm = pack('H*', $reset);
			$reset = substr($confirm, 5);
			
			if(!strpos($reset, ';')) {
				self::error('invalid_token');
				return;
			}
			
			$name = explode(';', $reset);
			$redirect = array_pop($name);
			$name = implode(';', $name);
			
			$r = 
				safe_row(
					'nonce, email',
					'txp_users',
					"name='".doSlash($name)."'"
				);
			
			$packed = pack('H*', substr(md5($r['nonce'] . $redirect), 0, 10)) . $name . ';' . $redirect;
			
			if(!$r || !$r['nonce'] || $confirm !== $packed) {
				sleep(3);
				self::error('invalid_token');
				return;
			}
			
			include_once txpath . '/lib/txplib_admin.php';
			include_once txpath . '/include/txp_auth.php';
			
			$pass = generate_password(12);
			$hash = txp_hash_password($pass);
			
			if(
				safe_update(
					'txp_users',
					"pass='".doSlash($hash)."',
					nonce='".doSlash(md5($name.pack('H*', md5(uniqid(mt_rand(), true)))))."'",
					"name='".doSlash($name)."'"
				) === false
			) {
				
				self::error('saving_failed');
				return;
			}
			
			$message = 
				gTxt('greeting').' '.$name.','.n.n.
				gTxt('your_password_is').': '.$password.n.n.
				gTxt('log_in_at').': '.hu.$redirect;
			
			$subject = 
				gTxt('mck_login_your_new_password', 
					array('{sitename}' => $sitename)
				);
			
			if(txpMail($r['email'], $subject, $message) === false) {
				self::error('could_not_mail');
				return;
			}
			
			callback_event('mck_login.reset_confirmed');
			
			header('Location: ' .hu.$redirect);
			
			$msg = 
				gTxt('mck_login_redirect_message', 
					array('{url}' => htmlspecialchars(hu.$redirect))
				);
			
			die($msg);
			return;
		}
		
		/*
			Log out
		*/
	
		if($logout && !$form && $is_logged_in) {
			
			self::$action = 'logout';
			
			callback_event('mck_login.logout');
			
			safe_update(
				'txp_users',
				"nonce='".doSlash(md5(uniqid(mt_rand(), TRUE)))."'",
				"name='".doSlash($is_logged_in['name'])."'"
			);
			
			setcookie('txp_login_public', '', time()-3600, mck_login_pub_path);
			setcookie('txp_login', '', time()-3600, mck_login_admin_path, mck_login_admin_domain);
			
			$_COOKIE['txp_login_public'] = '';
			return;
		}
		
		/*
			Log in
		*/
		
		if(!$form || $is_logged_in || !strpos($form, ';'))
			return;
		
		self::$action = 'login';
		
		callback_event('mck_login.login');
		
		if(!$pass || !$name) {
			self::error('name_and_pass_required');
			return;
		}
		
		$form = explode(';', (string) $form);
		
		if($form[1] != md5($form[0] . get_pref('blog_uid'))) {
			self::error('invalid_token');
			return;
		}
		
		if((int) $form[0] < @strtotime('-30 minutes')) {
			self::error('form_expired');
			return;
		}
			
		include_once txpath . '/include/txp_auth.php';
			
		if(txp_validate($name, $pass, false) === false) {
			callback_event('mck_login.invalid_login');
			self::error('invalid_login');
			sleep(3);
			return;
		}
		
		$c_hash = md5(uniqid(mt_rand(), true));
		$nonce = md5($name.pack('H*', $c_hash));
		$value = substr(md5($nonce), -10).$name;
		$privs = fetch('privs', 'txp_users', 'name', $name);
		
		safe_update(
			'txp_users',
			"nonce='".doSlash($nonce)."',
			last_access=now()",
			"name='".doSlash($name)."'"
		);
		
		setcookie(
			'txp_login_public',
			$value,
			$stay ? time()+3600*24*30 : 0,
			mck_login_pub_path
		);
		
		if($privs > 0) {
			setcookie(
				'txp_login',
				$name.','.$c_hash,
				$stay ? time()+3600*24*365 : 0,
				mck_login_admin_path,
				mck_login_admin_domain
			);
		}
		
		$_COOKIE['txp_login_public'] = $value;
		
		callback_event('mck_login.logged_in');
	}

	/**
	 * Send password reset confirmation message
	 * @param array $atts
	 * @return bool
	 * @access private
	 */

	static public function send_reset($atts) {
		
		extract(doArray(array(
			'name' => ps('mck_reset_name'),
			'form' => ps('mck_reset_form'),
		), 'trim'));
		
		$is_logged_in = mck_login(true) !== false;
		
		if(!$form || !strpos($form, ';') || $is_logged_in) {
			return false;
		}
		
		self::$action = 'reset';
		
		callback_event('mck_login.reset');
		
		$form = explode(';', (string) $form);
		
		if($form[1] != md5($form[0] . get_pref('blog_uid'))) {
			self::error('invalid_token');
			return false;
		}
		
		if((int) $form[0] < @strtotime('-30 minutes')) {
			self::error('form_expired');
			return false;
		}
		
		$r = 
			safe_row(
				'email, nonce',
				'txp_users',
				"name='".doSlash($name)."'"
			);
		
		if(!$r) {
			self::error('invalid_username');
			return false;
		}
		
		$confirm = 
			bin2hex(
				pack('H*', substr(md5($r['nonce'] . $atts['go_to_after']), 0, 10)). 
				$name . ';' . $atts['go_to_after']
			);
		
		$message = 
			gTxt('greeting').' '.$name.','.n.n.
			gTxt('password_reset_confirmation').': '.n.n.
			hu.'?mck_reset='.$confirm;
		
		if(txpMail($r['email'], $atts['subject'], $message) === false) {
			self::error('could_not_mail');
			return false;
		}
		
		callback_event('mck_login.reset_sent');
		return true;
	}

	/**
	 * Save a new user
	 * @param array $atts
	 * @return bool
	 * @see generate_password(), txp_hash_password()
	 * @access private
	 */

	static public function add_user($atts) {
	
		extract(doArray(array(
			'email' => ps('mck_register_email'),
			'name' => ps('mck_register_name'),
			'RealName' => ps('mck_register_realname'),
			'form' => ps('mck_register_form'),
		), 'trim'));
		
		if(!$form || !strpos($form, ';'))
			return false;
		
		self::$action = 'register';

		callback_event('mck_login.register');
		
		if(self::$form_errors)
			return false;
		
		$ip = remote_addr();
		
		if(is_blacklisted($ip)) {
			self::error('ip_blacklisted');
			return false;
		}
		
		if(fetch('ip', 'txp_discuss_ipban', 'ip', $ip)) {
			self::error('you_have_been_banned');
			return false;
		}
		
		if(!$email || !$name || !$RealName) {
			self::error('all_fields_required');
			return false;
		}
		
		$form = explode(';', (string) $form);
		
		if($form[1] != md5($form[0] . get_pref('blog_uid'))) {
			self::error('invalid_token');
			return false;
		}
		
		if((int) $form[0] < @strtotime('-30 minutes')) {
			self::error('form_expired');
			return false;
		}
		
		if(self::field_strlen($email) > 100)
			self::error('email_too_long');
		
		elseif(!is_valid_email($email))
			self::error('invalid_email');
		
		if(self::field_strlen($name) < 3)
			self::error('username_too_short');
		
		elseif(self::field_strlen($name) > 64)
			self::error('username_too_long');
		
		if(self::field_strlen($RealName) > 64)
			self::error('realname_too_long');
		
		if(self::error())
			return false;
		
		if(
			safe_row(
				'name', 
				'txp_users',
				"name='".doSlash($name)."' OR email='".doSlash($email)."' LIMIT 0, 1"
			)
		) {
		
			if(fetch('email', 'txp_users', 'email', $email)) {
				self::error('email_in_use');
			}
		
			self::error('username_taken');
			return false;
		}
		
		sleep(3);
	
		include_once txpath . '/lib/txplib_admin.php';
		include_once txpath . '/include/txp_auth.php';
	
		$password = generate_password(12);
		$hash = txp_hash_password($password);
		$privs = (int) $atts['privs'];

		if(
			safe_insert(
				'txp_users',
				"privs='{$privs}', 
				name='".doSlash($name)."',
				email='".doSlash($email)."',
				RealName='".doSlash($RealName)."',
				nonce='".doSlash(md5(uniqid(mt_rand(), true)))."',
				pass='".doSlash($hash)."'"
			) === false
		) {
			self::error('saving_failed');
			return false;
		}
		
		$message = 
			gTxt('greeting').' '.$name.','.
			n.n.gTxt('your_password_is').': '.$password.
			n.n.gTxt('log_in_at').': '.$atts['log_in_url'];
		
		if(txpMail($email, $atts['subject'], $message) === false) {
			self::error('could_not_mail');
			return false;
		}
		
		callback_event('mck_login.registered');
		return true;
	}

	/**
	 * Save a new password
	 * @return bool
	 * @see txp_validate(), txp_hash_password()
	 * @access private
	 */

	static public function save_password() {
		
		extract(doArray(array(
			'old_pass' => ps('mck_password_old'),
			'new_pass' => ps('mck_password_new'),
			'confirm_pass' => ps('mck_password_confirm'),
			'token' => ps('mck_login_token'),
			'form' => ps('mck_password_form'),
		), 'trim'));
		
		if(!$form || mck_login(true) === false)
			return false;
		
		self::$action = 'password';
		
		callback_event('mck_login.save_password');
		
		if(self::error())
			return false;
		
		if(!$old_pass || !$new_pass || !$confirm_pass) {
			self::error('all_fields_required');
			return false;
		}
		
		if($token != mck_login_token()) {
			self::error('invalid_csrf_token');
			return false;
		}
		
		$length = function_exists('mb_strlen') ? 
			mb_strlen($new_pass, 'UTF-8') : strlen($new_pass);
		
		if(6 > $length)
			self::error('password_too_short');
		
		if($new_pass !== $old_pass)
			self::error('passwords_do_not_match');
		
		$name = mck_login(array('name' => 'name'));
		
		include_once txpath . '/include/txp_auth.php';
			
		if(txp_validate($name, $old_pass, false) === false) {
			self::error('old_password_incorrect');
			sleep(3);
		}
		
		if(self::error())
			return false;
		
		$hash = txp_hash_password($new_pass);
		
		if(
			safe_update(
				'txp_users',
				"pass='".doSlash($hash)."'",
				"name='".doSlash($name)."'"
			) === false
		) {
			self::error('saving_failed');
			return false;
		}
		
		callback_event('mck_login.password_saved');
	}
	
	/**
	 * Get string length for pre-save validation.
	 * @param string $str
	 * @return int
	 * @see DB::DB()
	 * @access private
	 */

	static public function field_strlen($str) {
		global $DB;
		
		$version = (int) @$DB->version[0];
		
		if(!function_exists('mb_strlen') || $version < 5)
			return strlen($str);
		
		return mb_strlen($str, 'UTF-8');
	}
}

/**
 * Password reset form
 * @param array $atts
 * @param string $atts[action] Form's action (target location)
 * @param string $atts[id] Form's HTML id.
 * @param string $atts[class] Form's HTML class.
 * @param string $atts[go_to_after] The page (page) the confirmation URL directs users. i.e. about/reset-page
 * @param string $atts[subject] Confirmation email's subject.
 * @param string $thing
 * @return string HTML markup
 * <code>
 *		<txp:mck_reset_form>
 *			<txp:mck_login_errors />
 *			<txp:mck_login_input type="text" name="mck_reset_name" />
 *			<button type="submit">Send reset request</button>
 *		<txp:else />
 *			Confirmation email has been sent with a reset link.
 *		</txp:mck_reset_form>
 * </code>
 */

	function mck_reset_form($atts, $thing=''){
	
		global $pretext, $sitename;
	
		$opt = lAtts(array(
			'action' => $pretext['request_uri'] . '#mck_reset_form',
			'id' => 'mck_reset_form',
			'class' => 'mck_reset_form',
			'go_to_after' => '',
			'subject' => '['.$sitename.'] '.gTxt('password_reset_confirmation_request'),
		), $atts);
		
		if(mck_login(true) !== false)
			return;
		
		$r = mck_login::send_reset($opt);
		extract($opt);
		
		if($r === true && !mck_login::error())
			return parse(EvalElse($thing, false));
		
		$token = ps('mck_reset_form');
		
		if(!$token || !mck_login::error()) {
			$timestamp = strtotime('now');
			$token = $timestamp.';'.md5($timestamp . get_pref('blog_uid'));
		}
		
		if(mck_login::error())
			$class .= ' mck_login_error';
		
		mck_login_errors('reset');
		
		$r =
			'<form method="post" id="'.htmlspecialchars($id).'" class="'.htmlspecialchars($class).'" action="'.htmlspecialchars($action).'">'.n.
				hInput('mck_reset_form', $token).n.
				parse(EvalElse($thing, true)).n.
				callback_event('mck_login.reset_form').
			'</form>';
		
		mck_login_errors(null);
		return $r;
	}

/**
 * Return user data
 * @param array|bool $atts
 * @param string $atts[name] Options: name, RealName, email, privs.
 * @param bool $atts[escape] Convert special characters to HTML entities.
 * @return mixed
 * @see is_logged_in()
 * <code>
 *		<txp:mck_login name="email" />
 * </code>
 */

	function mck_login($atts){
		static $data = NULL;
		
		if($data === NULL) {
			$data = is_logged_in();
		}
		
		if($atts === true) {
			return $data;
		}
	
		extract(lAtts(array(
			'name' => 'RealName',
			'escape' => 1,
		),$atts));

		if(!$data || !isset($data[$name]))
			return;
		
		return $escape ? htmlspecialchars($data[$name]) : $data[$name];
	}

/**
 * Check if the user is logged in, or that the data matches the value
 * @param array $atts
 * @param string $atts[name] If NULL (unset), checks if visitor is logged in.
 * @param string $atts[value] Match to.
 * @param string $thing
 * @return string
 * @see mck_login()
 * <code>
 *		<txp:mck_login_if>
 *			User is logged in.
 *		<txp:else />
 *			User is not logged in.
 *		</txp:mck_login_if>
 * </code>
 */

	function mck_login_if($atts, $thing) {
	
		extract(lAtts(array(
			'name' => NULL,
			'value' => '',
		),$atts));
		
		$data = mck_login(true);

		if($name === NULL) {
			$r = $data !== false;
		}
		
		else {
			$r = isset($data[$name]) && $data[$name] == $value;
		}
		
		return parse(EvalElse($thing, $r));
	}

/**
 * Register form
 * @param array $atts
 * @param int $atts[privs] Privileges the user is created with.
 * @param string $atts[action] Form's action (target location).
 * @param string $atts[id] Form's HTML id. 
 * @param string $atts[class] Form's HTML class.
 * @param string $atts[log_in_url] "Log in at" URL used in the sent email.
 * @param string $atts[subject] Email message's subject.
 * @param string $thing
 * @return string HTML markup.
 * <code>
 *		<txp:mck_register_form>
 *			<txp:mck_login_errors />
 *			<txp:mck_login_input type="text" name="mck_register_email" />
 *			<txp:mck_login_input type="text" name="mck_register_name" />
 *			<txp:mck_login_input type="text" name="mck_register_realname" />
 *			<button type="submit">Register</button>
 *		<txp:else />
 *			Email sent with your login details.
 *		</txp:mck_register_form>
 * </code>
 */

	function mck_register_form($atts, $thing=''){
	
		global $pretext, $sitename;
	
		$opt = lAtts(array(
			'privs' => 0,
			'action' => $pretext['request_uri'].'#mck_register_form',
			'id' => 'mck_register_form',
			'class' => 'mck_register_form',
			'log_in_url' => hu,
			'subject' => '['.$sitename.'] '.gTxt('your_new_password'),
		), $atts);
		
		$r = mck_login::add_user($opt);
		extract($opt);
		
		if($r === true && !mck_login::error())
			return parse(EvalElse($thing, false));
		
		$token = ps('mck_register_form');
		
		if(!$token || mck_login::error()) {
			$timestamp = strtotime('now');
			$token = $timestamp.';'.md5($timestamp . get_pref('blog_uid'));
		}
		
		if(mck_login::error())
			$class .= ' mck_login_error';
		
		mck_login_errors('register');
		
		$r =
			'<form method="post" id="'.htmlspecialchars($id).'" class="'.htmlspecialchars($class).'" action="'.htmlspecialchars($action).'">'.n.
				hInput('mck_register_form', $token).n.
				parse(EvalElse($thing, true)).n.
				callback_event('mck_login.register_form').
			'</form>';
		
		mck_login_errors(null);
		
		return $r;
	}

/**
 * Displays a login form
 * @param array $atts
 * @param string $atts[action] Form's action (target location).
 * @param string $atts[id] Form's HTML id.
 * @param string $atts[class] Form's HTML class.
 * @param string $thing
 * @return string HTML markup.
 * <code>
 *		<txp:mck_login_form>
 *			<txp:mck_login_errors />
 *			<txp:mck_login_input type="text" name="mck_login_name" />
 *			<txp:mck_login_input type="password" name="mck_login_pass" />
 *			<button type="submit">Log in</button>
 *		<txp:else />
 *			You are logged in. <a href="?mck_logout=1">Log out</a>.
 *		</txp:mck_login_form>
 * </code>
 */

	function mck_login_form($atts, $thing=''){
		
		global $pretext;
	
		extract(lAtts(array(
			'action' => $pretext['request_uri'].'#mck_login_form',
			'id' => 'mck_login_form',
			'class' => 'mck_login_form',
		), $atts));
		
		if(mck_login(true) !== false)
			return parse(EvalElse($thing, false));
		
		$token = ps('mck_login_form');
		
		if(!$token || mck_login::error()) {
			$timestamp = strtotime('now');
			$token = $timestamp.';'.md5($timestamp . get_pref('blog_uid'));
		}
		
		if(mck_login::error())
			$class .= 'mck_login_error';
		
		mck_login_errors('login');
		
		$thing = 
			'<form method="post" id="'.htmlspecialchars($id).'" class="'.htmlspecialchars($class).'" action="'.htmlspecialchars($action).'">'.n.
				hInput('mck_login_form', $token).n.
				parse(EvalElse($thing, true)).n.
				callback_event('mck_login.login_form').
			'</form>';
		
		mck_login_errors(null);
		
		return $thing;
	}

/**
 * Displays password changing form
 * @param array $atts
 * @param string $atts[action] Form's action (target location).
 * @param string $atts[id] Form's HTML id.
 * @param string $atts[class] Form's HTML class.
 * @param string $thing
 * @return string HTML markup
 * <code>
 *		<txp:mck_password_form>
 *			<txp:mck_login_errors />
 *			<txp:mck_login_input type="password" name="mck_password_old" />
 *			<txp:mck_login_input type="password" name="mck_password_new" />
 *			<txp:mck_login_input type="password" name="mck_password_confirm" />
 *			<button type="submit">Save new password</button>
 *		<txp:else />
 *			Password changed.
 *		</txp:mck_password_form>
 * </code>
 */

	function mck_password_form($atts, $thing='') {
	
		global $pretext;
		
		extract(lAtts(array(
			'action' => $pretext['request_uri'].'#mck_password_form',
			'id'=> 'mck_password_form',
			'class' => 'mck_password_form',
		), $atts));
		
		if(mck_login(true) === false)
			return;
		
		$r = mck_login::save_password();
		
		if($r === true && !mck_login::error())
			return parse(EvalElse($thing, false));
		
		if(mck_login::error())
			$class .= 'mck_login_error';
		
		mck_login_errors('password');
		
		$thing = 
			'<form method="post" id="'.htmlspecialchars($id).'" class="'.htmlspecialchars($class).'" action="'.htmlspecialchars($action).'">'.n.
				hInput('mck_login_token', mck_login_token()).n.
				hInput('mck_password_form', 1).n.
				parse(EvalElse($thing, true)).n.
				callback_event('mck_login.password_form').
			'</form>';
		
		mck_login_errors(null);

		return $thing;
	}

/**
 * Generates HTML form inputs
 * @param array $atts Array of HTML input's attributes. i.e. array('type' => 'password', ...)
 * @return string HTML markup
 * <code>
 *		<txp:mck_login_input type="text" name="foo" value="bar" />
 * </code>
 */

	function mck_login_input($atts) {
	
		static $uid = 1;
		
		$r = lAtts(array(
			'type' => 'text',
			'name' => '',
			'value' => '',
			'class' => 'mck_login_input',
			'id' => '',
			'label' => '',
			'required' => 1,
			'remember' => 1,
		), $atts, 0);
		
		extract($r);
		
		if($type == 'token') {
			return hInput('mck_login_token', mck_login_token());
		}
		
		if($required) {
			$r['class'] .= ' mck_login_required';
		}
		
		if(isset($_POST[$name])) {
			
			if($type == 'checkbox' && ps($name) == $value)
				$r['checked'] = 'checked';
			
			if($type != 'password' && $remember)
				$r['value'] = ps($name);
			
			if(ps($name) === '' && $required) {
				$r['class'] .= ' mck_login_error';
			}
		}
		
		if(!$id && $uid++)
			$r['id'] = 'mck_login_' . md5($name . $uid);
		
		if($label)
			$label = '<label for="'.htmlspecialchars($r['id']).'">'.
				htmlspecialchars($r['label']).'</label>'.n;
		
		$r = array_merge((array) $atts, (array) $r);
		unset($r['label']);
		
		if($required != 'required')
			unset($r['required']);
		
		$out = array();
		
		foreach($r as $name => $value)
			if($value !== '' || $name == 'value')
				$out[] = htmlspecialchars($name).'="'.htmlspecialchars($value).'"';
		
		return $label . '<input '. implode(' ', $out).' />';
	}

/**
 * Displays error messages
 * @param array|string $atts
 * @param string $atts[for] Sets which form's errors are shown. Either login, reset, password, register.
 * @param string $atts[wraptag] HTML wraptag.
 * @param string $atts[break] HTML tag used to separate the items.
 * @param string $atts[class] Wraptag's HTML class.
 * @param int $atts[offset] Skip number of errors from the beginning.
 * @param int $atts[limit] Limit number of shown errors.
 * @return string HTML markup
 * <code>
 *		<txp:mck_login_errors for="reset" wraptag="p" break="" />
 * </code>
 */

	function mck_login_errors($atts) {
		
		static $parent = NULL;
		
		if(is_string($atts) || $atts === NULL) {
			$parent = $atts;
			mck_login::$action = $atts;
			return;
		}
		
		extract(lAtts(array(
			'for' => $parent,
			'wraptag' => 'ul',
			'break' => 'li',
			'class' => '',
			'offset' => 0,
			'limit' => NULL,
		), $atts));
		
		$r = mck_login::error();
		
		if(!$r)
			return;
			
		if($offset || $limit)
			$r = array_slice($r, $offset, $limit);
		
		$out = array();
		
		foreach($r as $msg) {
			$pfx = gTxt('mck_login_'.$msg);
			
			$out[] = 
				'<span class="mck_login_error_'.md5($msg).'">'.
					($pfx == 'mck_login_' . $msg  ? gTxt($msg) : $pfx).
				'</span>';
		}
		
		return $out ? doWrap($out, $wraptag, $break, $class) : '';
	}

/**
 * Generate a ciphered token.
 * @return string
 * <code>
 *		<txp:mck_login_token />
 * </code>
 */

	function mck_login_token() {
		
		static $token;
		
		if(!$token) {

			$nonce = 
				fetch(
					'nonce', 'txp_users', 'name', 
					mck_login(array('name' => 'name'))
				);
			
			$token = md5($nonce . get_pref('blog_uid'));
		}
		
		return $token;
	}

/**
 * Bouncer. Checks token, and protects against CSRF attempts.
 * @param mixed $void
 * @param string $thing
 * @return mixed
 * <code>
 *		<txp:mck_login_bouncer />
 * </code>
 */

	function mck_login_bouncer($void=NULL, $thing=NULL) {
		if(gps('mck_login_token') != mck_login_token()) {
			
			sleep(3);
		
			if($thing !== NULL)
				return false;
			
			txp_die(gTxt('mck_login_invalid_csrf_token'), '401');
		}
		
		if($thing !== NULL && !$void)
			return parse($thing);
	}

?>