<?php

/**
 * This is an example plugin for mck_login. Showcases extending.
 *
 * @package mck_login
 * @author Jukka Svahn
 *
 * The plugin will add a spam trap field to mck_login's self-registering form.
 * If the spam trap field is filled, registering is prevented.
 */
 
 	register_callback('abc_trap_html', 'mck_login.register_form');
 	register_callback('abc_trap_validate', 'mck_login.register');

/**
 * Adds trap fields to the HTML form
 * @return string HTML markup
 * @see fInput(), ps()
 */

	function abc_trap_html() {
		echo 
			'<div style="display: none;">'.n.
				fInput('text', 'phone', ps('phone')).n.
			'</div>';
	}

/**
 * Add extra validation for the trap to the form processing step.
 * @return nothing
 * @see mck_login::error(), ps()
 */

	function abc_trap_validate() {
		if(ps('phone')) {
		
			/*
				Field named "phone" (the spam trap) was filled.
				mck_login::error() is used to add form validation error.
			*/
		
			mck_login::error('abc_trap_marking_as_spam');
		}
	}

?>