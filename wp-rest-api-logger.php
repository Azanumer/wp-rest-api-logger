<?php
/**
 * Plugin Name:       REST API Logger
 * Plugin URI:        https://github.com/Azanumer/wp-rest-api-logger
 * Description:       Logs every WordPress REST API request — route, method, status, duration, IP and user — with a filterable Tools page viewer, retention pruning and an errors-only mode.
 * Version:           1.0.0
 * Author:            Azan Umer
 * Author URI:        https://azanumer.cv
 * License:           MIT
 * License URI:       https://opensource.org/licenses/MIT
 * Text Domain:       wp-rest-api-logger
 * Requires at least: 5.8
 * Requires PHP:      7.4
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WRAL_VERSION', '1.0.0' );
define( 'WRAL_TABLE', 'wral_logs' );
define( 'WRAL_OPTION', 'wral_settings' );

/**
 * Default settings.
 *
 * @return array
 */
function wral_default_settings() {
	return array(
		'enabled'         => 1,
		'retention_days'  => 30,
		'errors_only'     => 0,
		'log_admin_users' => 1,
		'excluded_routes' => "/wp/v2/users/me\n/wp-json/\n",
	);
}

/**
 * Get settings merged over defaults.
 *
 * @return array
 */
function wral_get_settings() {
	$saved = get_option( WRAL_OPTION, array() );
	if ( ! is_array( $saved ) ) {
		$saved = array();
	}
	return array_merge( wral_default_settings(), $saved );
}

/**
 * Full table name.
 *
 * @return string
 */
function wral_table() {
	global $wpdb;
	return $wpdb->prefix . WRAL_TABLE;
}

/**
 * Create the log table. Runs on activation and on admin_init as a safety net.
 */
function wral_create_table() {
	global $wpdb;
	$table   = wral_table();
	$charset = $wpdb->get_charset_collate();
	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	$sql = "CREATE TABLE {$table} (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		method varchar(10) NOT NULL DEFAULT '',
		route varchar(255) NOT NULL DEFAULT '',
		status smallint(5) unsigned NOT NULL DEFAULT 0,
		duration_ms mediumint(8) unsigned NOT NULL DEFAULT 0,
		ip varchar(45) NOT NULL DEFAULT '',
		user_id bigint(20) unsigned NOT NULL DEFAULT 0,
		created_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
		PRIMARY KEY (id),
		KEY route (route(191)),
		KEY status (status),
		KEY created_at (created_at)
	) {$charset};";
	dbDelta( $sql );
}
register_activation_hook( __FILE__, 'wral_create_table' );
add_action( 'admin_init', 'wral_create_table' );

/**
 * Client IP, honouring trusted-proxy headers via the same logic other
 * plugins in this series use (right-to-left walk of X-Forwarded-For).
 *
 * @return string
 */
function wral_client_ip() {
	if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
		return sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
	}
	if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
		$parts = array_map( 'trim', explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) ) );
		// Right-most entry is the closest proxy; walk left until a public IP.
		for ( $i = count( $parts ) - 1; $i >= 0; $i-- ) {
			if ( filter_var( $parts[ $i ], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
				return $parts[ $i ];
			}
		}
		return end( $parts );
	}
	return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
}

/* ------------------------------------------------------------------ */
/*  Logging                                                            */
/* ------------------------------------------------------------------ */

$GLOBALS['wral_request_started_at'] = null;

/**
 * Record the request start time (microtime) before dispatch.
 *
 * @param mixed            $result  Pre-dispatch result (null = proceed).
 * @param WP_REST_Server   $server  Server instance.
 * @param WP_REST_Request  $request Request object.
 * @return mixed Unchanged.
 */
function wral_mark_start( $result, $server, $request ) {
	$GLOBALS['wral_request_started_at'] = microtime( true );
	return $result;
}
add_filter( 'rest_pre_dispatch', 'wral_mark_start', 10, 3 );

/**
 * Log the finished request.
 *
 * @param mixed           $result  Response object or WP_Error.
 * @param WP_REST_Server  $server  Server instance.
 * @param WP_REST_Request $request Request object.
 * @return mixed Unchanged.
 */
function wral_log_request( $result, $server, $request ) {
	$settings = wral_get_settings();
	if ( empty( $settings['enabled'] ) ) {
		return $result;
	}

	// Only log real HTTP REST requests — rest_do_request() sub-requests
	// from inside plugins/themes/cron run without REST_REQUEST defined.
	if ( ! defined( 'REST_REQUEST' ) || ! REST_REQUEST ) {
		return $result;
	}

	$route = $request->get_route();
	if ( ! is_string( $route ) || '' === $route ) {
		return $result;
	}

	// Excluded routes: one substring pattern per line.
	$excluded = array_filter( array_map( 'trim', explode( "\n", (string) $settings['excluded_routes'] ) ) );
	foreach ( $excluded as $pattern ) {
		if ( false !== strpos( $route, $pattern ) ) {
			return $result;
		}
	}

	if ( $result instanceof WP_Error ) {
		$data   = $result->get_error_data();
		$status = isset( $data['status'] ) ? (int) $data['status'] : 500;
	} elseif ( $result instanceof WP_REST_Response ) {
		$status = (int) $result->get_status();
	} else {
		$status = 200;
	}

	if ( ! empty( $settings['errors_only'] ) && $status < 400 ) {
		return $result;
	}

	$user_id = get_current_user_id();
	if ( empty( $settings['log_admin_users'] ) && $user_id && user_can( $user_id, 'manage_options' ) ) {
		return $result;
	}

	$started = $GLOBALS['wral_request_started_at'];
	$duration_ms = null !== $started ? (int) round( ( microtime( true ) - $started ) * 1000 ) : 0;

	global $wpdb;
	$wpdb->insert(
		wral_table(),
		array(
			'method'      => strtoupper( substr( $request->get_method(), 0, 10 ) ),
			'route'       => substr( $route, 0, 255 ),
			'status'      => $status,
			'duration_ms' => $duration_ms,
			'ip'          => substr( wral_client_ip(), 0, 45 ),
			'user_id'     => $user_id,
			'created_at'  => current_time( 'mysql' ),
		),
		array( '%s', '%s', '%d', '%d', '%s', '%d', '%s' )
	);

	return $result;
}
add_filter( 'rest_post_dispatch', 'wral_log_request', 10, 3 );

/**
 * Daily pruning of rows older than the retention window.
 */
function wral_prune_old_logs() {
	global $wpdb;
	$days = (int) wral_get_settings()['retention_days'];
	if ( $days <= 0 ) {
		return;
	}
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM " . wral_table() . " WHERE created_at < DATE_SUB( %s, INTERVAL %d DAY )",
			current_time( 'mysql' ),
			$days
		)
	);
}
add_action( 'wral_daily_prune', 'wral_prune_old_logs' );

if ( ! wp_next_scheduled( 'wral_daily_prune' ) ) {
	wp_schedule_event( time(), 'daily', 'wral_daily_prune' );
}
register_deactivation_hook(
	__FILE__,
	function () {
		wp_clear_scheduled_hook( 'wral_daily_prune' );
	}
);

/* ------------------------------------------------------------------ */
/*  Tools page                                                         */
/* ------------------------------------------------------------------ */

/**
 * Register Tools → REST API Log.
 */
function wral_register_tools_page() {
	add_management_page(
		__( 'REST API Log', 'wp-rest-api-logger' ),
		__( 'REST API Log', 'wp-rest-api-logger' ),
		'manage_options',
		'wp-rest-api-logger',
		'wral_render_tools_page'
	);
}
add_action( 'admin_menu', 'wral_register_tools_page' );

function wral_render_tools_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'wp-rest-api-logger' ) );
	}
	global $wpdb;

	// Save settings.
	if ( isset( $_POST['wral_save_settings'] ) ) {
		check_admin_referer( 'wral_save_settings' );
		update_option(
			WRAL_OPTION,
			array(
				'enabled'         => isset( $_POST['wral_enabled'] ) ? 1 : 0,
				'retention_days'  => max( 1, (int) ( $_POST['wral_retention_days'] ?? 30 ) ),
				'errors_only'     => isset( $_POST['wral_errors_only'] ) ? 1 : 0,
				'log_admin_users' => isset( $_POST['wral_log_admin_users'] ) ? 1 : 0,
				'excluded_routes' => isset( $_POST['wral_excluded_routes'] ) ? sanitize_textarea_field( wp_unslash( $_POST['wral_excluded_routes'] ) ) : '',
			)
		);
		echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Settings saved.', 'wp-rest-api-logger' ) . '</p></div>';
	}

	// Clear all logs.
	if ( isset( $_POST['wral_clear_logs'] ) ) {
		check_admin_referer( 'wral_clear_logs' );
		$wpdb->query( 'TRUNCATE TABLE ' . wral_table() );
		echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'All log entries deleted.', 'wp-rest-api-logger' ) . '</p></div>';
	}

	$settings = wral_get_settings();

	// Filters.
	$filter_method = isset( $_GET['method'] ) ? sanitize_key( wp_unslash( $_GET['method'] ) ) : '';
	$filter_status = isset( $_GET['status'] ) ? sanitize_key( wp_unslash( $_GET['status'] ) ) : '';
	$filter_route  = isset( $_GET['route'] ) ? sanitize_text_field( wp_unslash( $_GET['route'] ) ) : '';
	$page          = max( 1, (int) ( $_GET['paged'] ?? 1 ) );
	$per_page      = 50;
	$offset        = ( $page - 1 ) * $per_page;

	$where  = array( '1=1' );
	$params = array();
	if ( '' !== $filter_method ) {
		$where[]  = 'method = %s';
		$params[] = strtoupper( $filter_method );
	}
	if ( 'error' === $filter_status ) {
		$where[] = 'status >= 400';
	} elseif ( 'ok' === $filter_status ) {
		$where[] = 'status < 400';
	}
	if ( '' !== $filter_route ) {
		$where[]  = 'route LIKE %s';
		$params[] = '%' . $wpdb->esc_like( $filter_route ) . '%';
	}
	$where_sql = implode( ' AND ', $where );

	$total = (int) $wpdb->get_var(
		$wpdb->prepare( 'SELECT COUNT(*) FROM ' . wral_table() . ' WHERE ' . $where_sql, $params ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	);
	$rows  = $wpdb->get_results(
		$wpdb->prepare(
			'SELECT * FROM ' . wral_table() . ' WHERE ' . $where_sql . ' ORDER BY id DESC LIMIT %d OFFSET %d', // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			array_merge( $params, array( $per_page, $offset ) )
		)
	);
	$pages = (int) ceil( $total / $per_page );

	$base_url = admin_url( 'tools.php?page=wp-rest-api-logger' );
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'REST API Log', 'wp-rest-api-logger' ); ?></h1>

		<form method="get" action="">
			<input type="hidden" name="page" value="wp-rest-api-logger" />
			<select name="method">
				<option value=""><?php esc_html_e( 'All methods', 'wp-rest-api-logger' ); ?></option>
				<?php foreach ( array( 'GET', 'POST', 'PUT', 'PATCH', 'DELETE' ) as $m ) : ?>
					<option value="<?php echo esc_attr( $m ); ?>" <?php selected( $filter_method, $m ); ?>><?php echo esc_html( $m ); ?></option>
				<?php endforeach; ?>
			</select>
			<select name="status">
				<option value=""><?php esc_html_e( 'All statuses', 'wp-rest-api-logger' ); ?></option>
				<option value="ok" <?php selected( $filter_status, 'ok' ); ?>><?php esc_html_e( 'Success (< 400)', 'wp-rest-api-logger' ); ?></option>
				<option value="error" <?php selected( $filter_status, 'error' ); ?>><?php esc_html_e( 'Errors (≥ 400)', 'wp-rest-api-logger' ); ?></option>
			</select>
			<input type="search" name="route" value="<?php echo esc_attr( $filter_route ); ?>" placeholder="<?php esc_attr_e( 'Filter by route…', 'wp-rest-api-logger' ); ?>" />
			<?php submit_button( __( 'Filter', 'wp-rest-api-logger' ), 'secondary', '', false ); ?>
		</form>

		<p><?php printf( esc_html__( '%s requests logged.', 'wp-rest-api-logger' ), esc_html( number_format_i18n( $total ) ) ); ?></p>

		<table class="widefat fixed striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Time', 'wp-rest-api-logger' ); ?></th>
					<th><?php esc_html_e( 'Method', 'wp-rest-api-logger' ); ?></th>
					<th><?php esc_html_e( 'Route', 'wp-rest-api-logger' ); ?></th>
					<th><?php esc_html_e( 'Status', 'wp-rest-api-logger' ); ?></th>
					<th><?php esc_html_e( 'Duration', 'wp-rest-api-logger' ); ?></th>
					<th><?php esc_html_e( 'IP', 'wp-rest-api-logger' ); ?></th>
					<th><?php esc_html_e( 'User', 'wp-rest-api-logger' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $rows ) ) : ?>
					<tr><td colspan="7"><?php esc_html_e( 'No requests logged yet.', 'wp-rest-api-logger' ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $rows as $row ) : ?>
						<tr>
							<td><?php echo esc_html( $row->created_at ); ?></td>
							<td><strong><?php echo esc_html( $row->method ); ?></strong></td>
							<td><code><?php echo esc_html( $row->route ); ?></code></td>
							<td><?php echo esc_html( $row->status ); ?></td>
							<td><?php echo esc_html( $row->duration_ms ); ?> ms</td>
							<td><?php echo esc_html( $row->ip ); ?></td>
							<td>
								<?php
								if ( $row->user_id ) {
									$user = get_userdata( (int) $row->user_id );
									echo $user ? esc_html( $user->user_login ) : esc_html__( '(deleted user)', 'wp-rest-api-logger' );
								} else {
									esc_html_e( '—', 'wp-rest-api-logger' );
								}
								?>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
			</tbody>
		</table>

		<?php
		if ( $pages > 1 ) {
			echo '<div class="tablenav"><div class="tablenav-pages">';
			echo paginate_links(
				array(
					'base'      => add_query_arg( 'paged', '%#%', $base_url ),
					'format'    => '',
					'current'   => $page,
					'total'     => $pages,
					'prev_text' => __( '&laquo; Previous', 'wp-rest-api-logger' ),
					'next_text' => __( 'Next &raquo;', 'wp-rest-api-logger' ),
				)
			);
			echo '</div></div>';
		}
		?>

		<hr />

		<h2><?php esc_html_e( 'Settings', 'wp-rest-api-logger' ); ?></h2>
		<form method="post" action="">
			<?php wp_nonce_field( 'wral_save_settings' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Enable logging', 'wp-rest-api-logger' ); ?></th>
					<td><label><input type="checkbox" name="wral_enabled" value="1" <?php checked( ! empty( $settings['enabled'] ) ); ?> /> <?php esc_html_e( 'Log REST API requests', 'wp-rest-api-logger' ); ?></label></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Errors only', 'wp-rest-api-logger' ); ?></th>
					<td><label><input type="checkbox" name="wral_errors_only" value="1" <?php checked( ! empty( $settings['errors_only'] ) ); ?> /> <?php esc_html_e( 'Only log responses with status ≥ 400', 'wp-rest-api-logger' ); ?></label></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Log admin users', 'wp-rest-api-logger' ); ?></th>
					<td><label><input type="checkbox" name="wral_log_admin_users" value="1" <?php checked( ! empty( $settings['log_admin_users'] ) ); ?> /> <?php esc_html_e( 'Include requests made by administrators', 'wp-rest-api-logger' ); ?></label></td>
				</tr>
				<tr>
					<th scope="row"><label for="wral_retention_days"><?php esc_html_e( 'Retention (days)', 'wp-rest-api-logger' ); ?></label></th>
					<td><input type="number" id="wral_retention_days" name="wral_retention_days" value="<?php echo esc_attr( (int) $settings['retention_days'] ); ?>" min="1" max="365" class="small-text" /></td>
				</tr>
				<tr>
					<th scope="row"><label for="wral_excluded_routes"><?php esc_html_e( 'Excluded routes', 'wp-rest-api-logger' ); ?></label></th>
					<td>
						<textarea id="wral_excluded_routes" name="wral_excluded_routes" rows="4" cols="50" class="large-text code"><?php echo esc_textarea( (string) $settings['excluded_routes'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'One substring per line. Any route containing it is not logged (handy for noisy health-check or heartbeat routes).', 'wp-rest-api-logger' ); ?></p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Save Settings', 'wp-rest-api-logger' ), 'primary', 'wral_save_settings' ); ?>
		</form>

		<form method="post" action="" onsubmit="return confirm('<?php echo esc_js( __( 'Delete ALL logged requests? This cannot be undone.', 'wp-rest-api-logger' ) ); ?>');">
			<?php wp_nonce_field( 'wral_clear_logs' ); ?>
			<?php submit_button( __( 'Clear All Logs', 'wp-rest-api-logger' ), 'delete', 'wral_clear_logs' ); ?>
		</form>
	</div>
	<?php
}
