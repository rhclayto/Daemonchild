#!/usr/local/bin/php
<?php
// Run as user 'www'.

use React\EventLoop\Factory;
use React\Socket\Server;
use React\Http\Request;
use React\Http\RequestHeaderParser;
use React\Http\Response;

require_once './vendor/autoload.php';

/*
 * Bootstrap Drupal & prepare the environment & daemon.
 */
 
try {
  // Set up $_SERVER variables that will stay the same during the daemon's lifetime.
  global $argv, $argc;
  $argc = NULL;
  $argv = NULL;
  $_SERVER['argc'] = NULL;
  $_SERVER['argv'] = NULL;
  $_SERVER['PHP_SELF'] = '/index.php';
  $_SERVER['SCRIPT_NAME'] = '/index.php';
  $_SERVER['SCRIPT_FILENAME'] = '/var/www/example/com/htdocs/backend/index.php';
  $_SERVER['DOCUMENT_ROOT'] = '/var/www/example/com/htdocs/backend';
  $_SERVER['CONTEXT_DOCUMENT_ROOT'] = '/var/www/example/com/htdocs/backend';
  $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
  $_SERVER['REMOTE_HOST'] = '127.0.0.1';
  $_SERVER['SERVER_NAME'] = 'dc.example.com';
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
  define('DRUPAL_ROOT', '/var/www/example/com/htdocs/backend');
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
  $dc_name = 'daemonchild:' . $pid;
  $port = '55' . $pid;
  // Staggering added to prevent all of the processes from restarting at the same time.
  $time_to_live = time() + 43200 + ((int) $pid * 120); // 12 hours from process start, give or take.
  $requests_served = 0;
  $request_limit = 100000 + ((int) $pid * 500);
  // Using FreeBSD 10.3. Make sure that 'sysctl hw.physmem' is available & that its output will work with the substr() position used here.
  $total_memory = substr(shell_exec('sysctl hw.physmem'), 12);
  $memory_limit = (int) $total_memory / 5;
  // $memory_limit = 3153958400;
  $is_restarting = FALSE;

  // Miscellaneous resettable variables.
  $requestHeaders = '';
  $returnContent = '';
  $this_source = '';
  $content = '';
  
  watchdog('daemonchild', 'Daemonchild !pid spawning on port !prt', array('!pid' => $pid, '!prt' => $port));
}
catch (Exception $e) {
  watchdog('daemonchild', 'Error bootstrapping Drupal: !error', array('!error' => $e->getMessage()));
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
  // After this daemonchild has been up & running for two seconds, tell HAProxy over the stats socket to begin routing new connections to this instance.
  $loop->addTimer(2, function() use ($dc_name, $pid) {
    shell_exec("echo 'enable server daemonchild/$dc_name' | /usr/local/bin/socat /var/haproxy/stats.socket stdio");
    watchdog('daemonchild', 'Registered process !pid with HAProxy.', array('!pid' => $pid));
  });
}
catch (Exception $e) {
  watchdog('daemonchild', 'Error creating React: !error', array('!error' => $e->getMessage()));
  shell_exec('/usr/local/bin/supervisorctl restart daemonchild:' . $pid);
}

// Respond to HTTP requests.
try {
  $http->on('request', function (Request $request, Response $response) use (&$requests_served, $pre_user, $server_before, $pid, $time_to_live, &$requestHeaders, &$returnContent, &$this_source, $socket, &$content, $loop, $request_limit, $memory_limit, $dc_name, $is_restarting) {
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
    // Call Drupal's hook_init hook functions on every request.
    module_invoke_all('init');
    
    // Handle requests.
    // Handle POST, PATCH, etc.
    $request->on('data', function($data) use ($request, $response, $method, &$requestHeaders, &$content) {
      $contentLength = isset($requestHeaders['Content-Length']) ? (int) $requestHeaders['Content-Length'] : 0;
      $content .= $data;
      if (strlen($content) >= $contentLength) {
        // Add the content to the $_POST superglobal, so RESTful can access it. Requires a patch to RESTful: RESTful usually uses file_get_contents('php://input'), but react http or stream does something to the data so that that way doesn't work. The patch allows RESTful to get the data from $_POST. This is, it seems, an abuse of $_POST, but whatever: http://stackoverflow.com/a/8893792 .
        $_POST = $content;
      }
    });
    
    // Finish the request, send the response, tear-down the request.
    $request->on('end', function () use ($request, $response, &$returnContent, &$requestHeaders, $this_source, &$requests_served, $pre_user, $server_before, $pid, $time_to_live, $socket, $loop, $memory_limit, $request_limit, $dc_name, $is_restarting, &$content) {
      // Update the count of requests served.
      $requests_served++;
      // Get the response body.
      // Start output buffering.
      ob_start();
      ob_start();
      // Run the request through a custom version of Drupal's menu router system.
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
      if (!empty($output_headers['Vary'])) {
        $vary_array = array_filter(array_map('trim', explode(',', $output_headers['Vary'])));
        array_push($vary_array, 'Accept-Encoding');
        $output_headers['Vary'] = implode(', ', $vary_array);
      }
      else {
        $output_headers['Vary'] = 'Accept-Encoding';
      }
      $status_code = $response_headers_array['status'];
      // Compression.
      // @todo Brotli is not currently working. It encodes fine but when transmitted to a browser all that is displayed in the body is 'Unexpected: "*"'. Fix it somehow.
      if (!empty($requestHeaders['Accept-Encoding'])) {
        $encodings = array_map('trim', explode(',', $requestHeaders['Accept-Encoding'][0]));
        /* if (function_exists('brotli_compress') && in_array('br', $encodings)) {
          $returnContent = brotli_compress($returnContent, 5, BROTLI_TEXT);
          $output_headers['Content-Encoding'] = 'br';
          $output_headers['Transfer-Encoding'] = 'br';
          $output_headers['Content-Length'] = strlen($returnContent);
        }
        elseif (in_array('deflate', $encodings)) { */
        if (in_array('deflate', $encodings)) {
          $returnContent = gzcompress($returnContent);
          $output_headers['Content-Encoding'] = 'deflate';
          $output_headers['Content-Length'] = strlen($returnContent);
        }
        elseif (in_array('gzip', $encodings)) {
          $returnContent = gzencode($returnContent);
          $output_headers['Content-Encoding'] = 'gzip';
          $output_headers['Content-Length'] = strlen($returnContent);
        }
      }
      // Write the headers & body, & send the package.
      $response->writeHead($status_code, $output_headers);
      $response->end($returnContent);
      
      // Tear down all the request variables, headers, etc.
      // watchdog('daemonchild', 'Tearing down process !pid', array('!pid' => $pid));
      $returnContent = '';
      $output_headers = [];
      $content = '';
      $this_source = '';
      unset($requestHeaders);
      // Remove the RESTful response object & its headers.
      $response_object = restful()->getResponse();
      $response_headers = $response_object->getHeaders();
      $response_values = $response_headers->__toArray();
      foreach ($response_values as $rKey => $rVal) {
        $response_headers->remove($rKey);
      }
      // $request_object = restful()->getRequest();
      // $request_object = NULL;
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
      // _ultimate_cron_out_of_memory_protection();
      ctools_shutdown_handler();
      // imageinfo_cache_file_submit_shutdown();
      // memcache_admin_shutdown();
      // UltimateCronLock:shutdown();
      // UltimateCronLockMemcache::shutdown();
      lock_release_all();
      _drupal_shutdown_function();

      // watchdog('daemonchild', 'requests_served on process !pid: !reqs', array('!pid' => $pid, '!reqs' => $requests_served));
    });
  });
  
  $http->on('error', function (Exception $error) use ($pid) {
    watchdog('daemonchild', 'Error in PID !pid during $http->on: !error', array('!pid' => $pid, '!error' => $error->getMessage()));
  });
}
catch (Exception $e) {
  watchdog('daemonchild', 'Error somewhere inside $http->on: !error', array('!error' => $e->getMessage()));
  shell_exec('/usr/local/bin/supervisorctl restart daemonchild:' . $pid);
}

/**
 * Periodic health checks & auto-recycling of the daemon.
 */
 
try {
  $loop->addPeriodicTimer(60, function() use (&$requests_served, $time_to_live, $pid, $socket, $loop, $request_limit, $memory_limit, $dc_name, $is_restarting) {
    $current_memory_usage = memory_get_usage();
    if (($current_memory_usage >= $memory_limit || $requests_served >= $request_limit || time() >= $time_to_live) && $is_restarting === FALSE) {
      $is_restarting = TRUE;
      // Tell HAProxy over the stats socket to stop routing new connections to this instance.
      shell_exec("echo 'disable server daemonchild/$dc_name' | /usr/local/bin/socat /var/haproxy/stats.socket stdio");
      watchdog('daemonchild', 'Unregistered process !pid with HAProxy.', array('!pid' => $pid));
      // Ten seconds from now, restart this process. The timer is necessary to allow the current requests to finish & to allow HAProxy time to stop routing new requests to the process.
      $loop->addTimer(10, function() use ($pid, $socket, $dc_name) {
        watchdog('daemonchild', 'Restarting daemonchild !pid.', array('!pid' => $pid));
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
  watchdog('daemonchild', 'Error during $loop->addPeriodicTimer: !error', array('!error' => $e->getMessage()));
  shell_exec('/usr/local/bin/supervisorctl restart daemonchild:' . $pid);
}


/**
 * Start the loop!
 */

try {
  $loop->run();
}
catch (Exception $e) {
  watchdog('daemonchild', 'Error running React loop: !error', array('!error' => $e->getMessage()));
  shell_exec('/usr/local/bin/supervisorctl restart daemonchild:' . $pid);
}
