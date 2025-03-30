<?php
session_start();

$max_requests = 10;
$time_frame = 60;
$block_time = 300;

$ip = $_SERVER['REMOTE_ADDR'];
$time = time();
$log_file = 'security_logs.txt';
$blocked_ips = 'blocked_ips.txt';

$blocked = file_exists($blocked_ips) ? file($blocked_ips, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
if (in_array($ip, $blocked)) {
    die("403 Forbidden");
}

if (!isset($_SESSION['requests'])) {
    $_SESSION['requests'] = [];
}
array_push($_SESSION['requests'], $time);

$_SESSION['requests'] = array_filter($_SESSION['requests'], function ($t) use ($time, $time_frame) {
    return ($t > $time - $time_frame);
});

if (count($_SESSION['requests']) > $max_requests) {
    file_put_contents($blocked_ips, "$ip\n", FILE_APPEND);
    die("403 Forbidden - Too Many Requests");
}

if (!isset($_SERVER['HTTP_USER_AGENT']) || preg_match('/(bot|crawl|spider)/i', $_SERVER['HTTP_USER_AGENT'])) {
    file_put_contents($blocked_ips, "$ip\n", FILE_APPEND);
    die("403 Forbidden - Bot Detected");
}

$log_entry = "[$time] IP: $ip | User-Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\n";
file_put_contents($log_file, $log_entry, FILE_APPEND);

?>