<?php
/**
 * Uninstall handler for REST API Logger.
 *
 * Drops the log table, removes settings and clears the pruning cron.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;
$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wral_logs' );
delete_option( 'wral_settings' );
wp_clear_scheduled_hook( 'wral_daily_prune' );
