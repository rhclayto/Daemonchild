#!/usr/local/bin/php
<?php
// Run as user 'www'.

use React\EventLoop\Factory;
use React\Socket\Server;
use React\Http\Request;
use React\Http\RequestHeaderParser;
use React\Http\Response;
use Drupal\Component\Plugin\PluginBase;

require_once './vendor/autoload.php';

/*
 * Bootstrap Drupal & prepare the environment & daemon.
 */
 
// Set up $_SERVER variables that will stay the same during the daemon's lifetime.
try {
  global $argv, $argc;
  $argc = NULL;
  $argv = NULL;
  $_SERVER['argc'] = NULL;
  $_SERVER['argv'] = NULL;
  $_SERVER['PHP_SELF'] = '/index.php';
  $_SERVER['SCRIPT_NAME'] = '/index.php';
  $_SERVER['SCRIPT_FILENAME'] = '/var/www/hosting/tellingua/com/htdocs/backend/index.php';
  $_SERVER['DOCUMENT_ROOT'] = '/var/www/hosting/tellingua/com/htdocs/backend';
  $_SERVER['CONTEXT_DOCUMENT_ROOT'] = '/var/www/hosting/tellingua/com/htdocs/backend';
  $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
  $_SERVER['REMOTE_HOST'] = '127.0.0.1';
  $_SERVER['SERVER_NAME'] = 'dc.tellingua.com';
  $_SERVER['SERVER_SOFTWARE'] = 'ReactPHP';
  $_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
  $_SERVER['REQUEST_METHOD'] = '';
  // Store the immutable $_SERVER variables for restoration after the request is over.
  $server_before = $_SERVER;
  // Empty these superglobals.
  $_GET = array();
  $_POST = array();
  $_COOKIE = array();

  // Bootstrap.
  // define('DRUPAL_ROOT', getcwd());
  define('DRUPAL_ROOT', '/var/www/hosting/tellingua/com/htdocs/backend');
  ini_set('display_errors', 0);
  include_once DRUPAL_ROOT . '/includes/bootstrap.inc';
  drupal_bootstrap(DRUPAL_BOOTSTRAP_FULL);
  ini_set('display_errors', 1);
  // Start Drupal as the anonymous user.
  global $user;
  // Store the anonymous user for resetting after every request.
  $pre_user = $GLOBALS['user'];
  // Turn off the output buffering that drupal is doing by default.
  // ob_end_flush();
  // No sessions (we're using RESTful auth tokens for any daemon access).
  ini_set('session.use_cookies', '0');
  ini_set('session.use_only_cookies', '0');
  ini_set('session.cookie_httponly', '0');
  unset($_SESSION);
  drupal_save_session(FALSE); 
  // Tell MySQL to keep the connection alive for 24 hours in the absence of any connection attempts.
  db_query("set wait_timeout = 86400"); // 24 hours in seconds.

  // Set up the daemon process.
  $pid = getenv('DAEMONCHILD_PROCESS');
  $port = '55' . $pid;
  $time_to_live = time() + 43200 + mt_rand(0, 90); // 12 hours from process start, give or take.
  $requests_served = 0;
  $request_limit = 100000;
  // Using FreeBSD 10.3. Make sure 'sysctl hw.physmem' is available & the output will work with the substr() position used here.
  $total_memory = substr(shell_exec('sysctl hw.physmem'), 12);
  $memory_limit = (int) $total_memory / 2;
  // $memory_limit = 3153958400;

  // Miscellaneous resettable variables.
  $requestHeaders = '';
  $returnContent = '';
  $this_source = '';
  $content = '';
  
  watchdog('daemonchild', 'Daemonchild @pid spawning on port @prt', array('@pid' => $pid, '@prt' => $port));
}
catch (Exception $e) {
  watchdog('daemonchild', 'Error bootstrapping Drupal: @error', array('@error' => $e->getMessage()));
  return;
}

/**
 * React loop & HTTP server.
 */

// Create the React loop, socket, & HTTP server.
try {
// $loop = Factory::create();
// Use the pecl-ev extension's loop for the best performance.
$loop = new React\EventLoop\ExtEvLoop();
// $loop = new React\EventLoop\StreamSelectLoop();
// Sleep briefly before creating the socket to prevent 'port in use' errors on restart.
sleep(0.1);
$socket = new Server($port, $loop);
$http = new React\Http\Server($socket);
}
catch (Exception $e) {
  watchdog('daemonchild', 'Error creating React: @error', array('@error' => $e->getMessage()));
  shell_exec('/usr/local/bin/supervisorctl restart daemonchild:' . $pid);
}

// Respond to HTTP requests.
try {
  $http->on('request', function (Request $request, Response $response) use (&$requests_served, $pre_user, $server_before, $pid, $time_to_live, &$requestHeaders, &$returnContent, &$this_source, $socket, &$content, $loop, $request_limit, $memory_limit) {
    // Restore the user to the default of 0.
    $GLOBALS['user'] = $pre_user;
    global $user;
    // Ensure mt_rand is reseeded, to prevent random values from one page load being exploited to predict random values in subsequent page loads.
    $seed = unpack("L", drupal_random_bytes(4));
    mt_srand($seed[1]);
    // Update the request time.
    $_SERVER['REQUEST_TIME'] = time();
    $_SERVER['REQUEST_TIME_FLOAT'] = microtime(TRUE);
    // Update the Drupal constant too. Requires the runkit7 extension: https://github.com/runkit7/runkit7
    runkit_constant_redefine('REQUEST_TIME', $_SERVER['REQUEST_TIME']);
    // Initialize the Drupal path.
    drupal_path_initialize();
    // Drupal's hook_boot, hook_exit, etc.
    bootstrap_invoke_all('boot');
    bootstrap_invoke_all('exit');
    bootstrap_invoke_all('language_init');
    // Update the request method.
    $method = $request->getMethod();
    $_SERVER['REQUEST_METHOD'] = $method;
    // Get the URL & set up the superglobals relating to it.
    $url = $request->getPath();
    // Prevent serving all non /api/* & /files/* URLs right here.
    if (strpos($url, '/api/') !== 0 && strpos($url, '/files/') !== 0) {
      watchdog('daemonchild', 'Not an API or /files/* URL.');
      $response->writeHead(403, array('Content-Type' => 'application/json; charset=utf-8', 'X-Powered-By' => 'Liberte, egalite, unite.'));
      $response->end(json_encode('Non.'));
      return;
    }
    // Continue with the URL wrangling.
    $this_path = ltrim($url, '/');
    $this_source = drupal_get_normal_path($this_path);
    $_GET['q'] = $this_source;
    $_SERVER['QUERY_STRING'] = $this_source;
    // Headers.
    $requestHeaders = $request->getHeaders();
    // Add the request headers to the $_SERVER superglobal array.
    foreach ($requestHeaders as $key => $value) {
      $caps_header = 'HTTP_' . strtoupper(str_replace('-', '_', $key));
      $_SERVER[$caps_header] = $value[0];
    }
    // @todo We may do this:
    // drupal_block_denied(ip_address());
    // We're behind a proxy, so we need X-Forwarded-For to work with ip_address().
    // Or perhaps a custom solution with Redis, rolling rate limiter, etc. Or better, add blocked IPs to pf firewall rules.
    // Or rate limit at HAProxy level.
    
    // Call Drupal's hook_init hook functions on every request.
    module_invoke_all('init');
    // Handle requests.
    // Handle POST, PATCH, etc.
    $request->on('data', function($data) use ($request, $response, $method, &$requestHeaders, &$content) {
      $contentLength = isset($requestHeaders['Content-Length']) ? (int) $requestHeaders['Content-Length'] : 0;
      $content .= $data;
      if (strlen($content) >= $contentLength) {
        if ($method === 'POST') {
          $_POST = $content;
        }
      }
    });
    // Finish the request, send the response, tear-down the request.
    $request->on('end', function () use ($request, $response, &$returnContent, $requestHeaders, $this_source, &$requests_served, $pre_user, $server_before, $pid, $time_to_live, $socket, $loop, $memory_limit, $request_limit) {
      // Update the count of requests served.
      $requests_served++;
      // Get the response body.
      /* @todo // If it's a filesystem request. (Maybe handle this in nginx instead.)
      if (file_exists($this_source)) {
        $content = file_get_contents($this_source);
      }
      // Otherwise, it's a Drupal request.
      else { */
      // Start output buffering.
      ob_start();
      ob_start();
      // @todo Shorten the PHP execution path by using custom functions for this.
      // Run the request through Drupal's menu router system.
      menu_execute_active_handler($this_source);
      // Push Drupal's response into the output buffer.
      $returnContent .= ob_get_clean();
      $returnContent .= ob_get_clean();
      // Build the React response headers & status code from the Drupal response headers & status code.
      $output_headers = array(
        'Expires' => 'Sun, 27 Apr 1975 05:00:00 GMT',
        'Cache-Control' => 'no-cache, must-revalidate, public, no-transform',
        // 'Strict-Transport-Security' => 'max-age=63072000; includeSubdomains; preload',
        'X-Download-Options' => 'noopen',
        'X-Robots-Tag' => 'noindex, nofollow, noarchive, nosnippet, noodp, notranslate, noimageindex',
        'Access-Control-Max-Age' => '600',
        // 'content-security-policy' => '"upgrade-insecure-requests',
        'X-Frame-Options' => 'SAMEORIGIN',
        'X-XSS-Protection' => '1; mode=block',
        'X-Content-Type-Options' => 'nosniff',
        // Idealisme.
        'X-Powered-By' => 'Liberte, egalite, unite.',
      );
      $response_headers_array = drupal_get_http_header();
      foreach ($response_headers_array as $header_key => $header_value) {
        if ($header_key !== 'date') {
          $output_headers[ucwords($header_key, '-')] = $header_value;
        }
      }
      $status_code = $response_headers_array['status'];
      $response->writeHead($status_code, $output_headers);
      $response->end($returnContent);
      
      // Tear down all the request variables, headers, etc.
      // watchdog('daemonchild', 'Tearing down process @pid', array('@pid' => $pid));
      $returnContent = '';
      $output_headers = [];
      unset($requestHeaders);
      // Important: Remove the RESTful response object & its headers.
      $response_object = restful()->getResponse();
      $response_headers = $response_object->getHeaders();
      $response_values = $response_headers->__toArray();
      foreach ($response_values as $rKey => $rVal) {
        $response_headers->remove($rKey);
      }
      $response_object = NULL;
      $response_headers = NULL;
      $response_values = NULL;
      $status_code = NULL;
      // Reset the superglobals.
      $_SERVER = $server_before;
      $_GET = array();
      $_POST = array();
      $_COOKIE = array();
      $GLOBALS['user'] = $pre_user;
      // Reset Drupal's static variables.
      drupal_static_reset();
      // Run Drupal shutdown functions.
      _ultimate_cron_out_of_memory_protection();
      ctools_shutdown_handler();
      // imageinfo_cache_file_submit_shutdown();
      // memcache_admin_shutdown();
      // UltimateCronLock:shutdown();
      UltimateCronLockMemcache::shutdown();
      lock_release_all();
      _drupal_shutdown_function();

      watchdog('daemonchild', 'requests_served on process @pid: @reqs', array('@pid' => $pid, '@reqs' => $requests_served));

      // Auto-recycling of the daemon.
      if ($requests_served >= $request_limit || time() >= $time_to_live) {
        // 100 milliseconds from now, restart this process. The timer is necessary to allow the current request to finish.
        $loop->addTimer(0.1, function() use ($pid, $socket) {
          watchdog('daemonchild', 'Restarting daemonchild @pid.', array('@pid' => $pid));
          // Tell MySQL to close this database connection after ten seconds.
          db_query("set wait_timeout = 10");
          // Close the React socket so that it stops accepting new requests while we're shutting down.
          $socket->close();
          // Tell supervisord to restart this process.
          shell_exec('/usr/local/bin/supervisorctl restart daemonchild:' . $pid);
        });
      }
      // @todo Error handling & logging.
    });
  });
  $http->on('error', function (Exception $error) {
    watchdog('daemonchild', 'Error during $http->on: @error', array('@error' => $error->getMessage()));
    shell_exec('/usr/local/bin/supervisorctl restart daemonchild:' . $pid);
  });
}
catch (Exception $e) {
  watchdog('daemonchild', 'Error somewhere inside $http->on: @error', array('@error' => $e->getMessage()));
  shell_exec('/usr/local/bin/supervisorctl restart daemonchild:' . $pid);
}

/**
 * Periodic health checks & auto-recycling of the daemon.
 */
try {
  $loop->addPeriodicTimer(30, function() use (&$requests_served, $time_to_live, $pid, $socket, $loop, $request_limit, $memory_limit) {
    $current_memory_usage = memory_get_usage();
    if ($current_memory_usage >= $memory_limit || $requests_served >= $request_limit || time() >= $time_to_live) {
      // 100 milliseconds from now, restart this process. The timer is necessary to allow the current request to finish.
      $loop->addTimer(0.1, function() use ($pid, $socket) {
        watchdog('daemonchild', 'Restarting daemonchild @pid.', array('@pid' => $pid));
        // Tell MySQL to close this database connection after ten seconds.
        db_query("set wait_timeout = 10");
        // Close the React socket so that it stops accepting new requests while we're shutting down.
        $socket->close();
        // Tell supervisord to restart this process.
        shell_exec('/usr/local/bin/supervisorctl restart daemonchild:' . $pid);
      });
    }
  });
}
catch (Exception $e) {
  watchdog('daemonchild', 'Error during $loop->addPeriodicTimer: @error', array('@error' => $e->getMessage()));
  shell_exec('/usr/local/bin/supervisorctl restart daemonchild:' . $pid);
}

// Start the loop!
try {
  $loop->run();
}
catch (Exception $e) {
  watchdog('daemonchild', 'Error running React loop: @error', array('@error' => $e->getMessage()));
  shell_exec('/usr/local/bin/supervisorctl restart daemonchild:' . $pid);
}
