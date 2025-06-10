<?php
session_start();
header('X-Robots-Tag: noindex, nofollow', true);
@set_time_limit(0);
@ignore_user_abort(true);
date_default_timezone_set('Asia/Jakarta');

$file_extensions = ['php', 'phtml', 'pht', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'ini', 'htaccess'];
$signatures = [
    'High-Risk' => [
        'Shell/Backdoor' => ['/\b(c99|r57|b374k|wso|webshell|IndoXploit|An0n_sHeLL)\b/i', '/`\s*\$_(GET|POST|REQUEST)\[\w+\]\s*`/i', '/\bpassthru\s*\(\s*\$_(GET|POST|REQUEST)\s*\[/'],
        'Code Obfuscation' => ['/\beval\s*\(\s*base64_decode\s*\(/i', '/\beval\s*\(\s*gzinflate\s*\(/i', '/\bstrrev\s*\(\s*["\'](edoced_46esab|tropmi|elif_etaerc)["\']/i'],
        'Callback/Dynamic Functions' => ['/\b(array_map|array_filter)\s*\(\s*["\'](assert|eval|system|exec|passthru)["\']/i', '/\$\w{6,}\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i', '/preg_replace\s*\(\s*["\'].*["\']\s*e\s*,/is']
    ],
    'Suspicious' => [
        'Risky Functions' => ['/\b(shell_exec|passthru|system|popen|pcntl_exec|proc_open)\s*\(/i', '/\b(symlink|link)\s*\(/i', '/\b(chmod|chown|chgrp)\s*\(/i', '/\b(assert)\s*\(\s*\$_(GET|POST|REQUEST)\s*\[/i'],
        'Remote Execution' => ['/\b(curl_exec|fsockopen|pfsockopen|stream_socket_client)\s*\(/i', '/(include|require)\s*\(?\s*\$_(GET|POST|REQUEST)\s*\[/i', '/file_get_contents\s*\(\s*["\'](http|ftp)s?:\/\//i'],
        'Info/Config Stealers' => ['/fopen\s*\(\s*["\'].*(wp-config|configuration|settings)\.php["\']\s*,\s*["\']r["\']\s*\)/i', '/shell_exec\s*\(\s*["\']mysqldump/i'],
        'WordPress Specific' => ['/\$wpdb->query\s*\(\s*\$_(GET|POST|REQUEST)\s*\[/i', '/php_value\s+auto_prepend_file/i', '/AddType\s+application\/x-httpd-php\s+\.(jpg|png|gif)/i']
    ]
];

function validate_path($path) {
    $real_path = realpath(trim($path));
    $doc_root = realpath($_SERVER['DOCUMENT_ROOT']);
    if ($real_path === false || strpos($real_path, $doc_root) !== 0) return false;
    return $real_path;
}

function make_accessible(&$path, &$log) { if (is_readable($path)) return true; $perms = is_dir($path) ? 0755 : 0644; if (@chmod($path, $perms)) { clearstatcache(); if (is_readable($path)) { $log[] = "Permissions adjusted for: " . htmlspecialchars($path); return true; } } $log[] = "Failed to adjust permissions for: " . htmlspecialchars($path); return false; }
function format_size($bytes) { if ($bytes >= 1048576) return number_format($bytes / 1048576, 2) . ' MB'; if ($bytes >= 1024) return number_format($bytes / 1024, 2) . ' KB'; return $bytes . ' bytes'; }
function get_process_list() { $output = 'Process execution functions (shell_exec, exec) are disabled on this server.'; if (function_exists('shell_exec')) { $output = shell_exec('ps aux'); } return htmlspecialchars($output); }
function highlight_processes($output) { $keywords = ['php', 'perl', 'python', 'sh', 'bash', 'sshd', 'apache', 'nginx', 'wget', 'curl', 'nc']; return preg_replace('/(\b(' . implode('|', $keywords) . ')\b)/i', '<span class="highlight">$1</span>', $output); }

if (isset($_GET['action']) && $_GET['action'] === 'view_source') {
    $file_path = base64_decode($_GET['path'] ?? '');
    $validated_path = validate_path($file_path);
    if ($validated_path && is_readable($validated_path)) {
        echo '<!DOCTYPE html><html><head><title>Source of ' . htmlspecialchars(basename($validated_path)) . '</title><style>body{background-color:#1e1e1e;font-family:monospace;font-size:14px;line-height:1.4;}pre{margin:0;}</style></head><body>';
        highlight_file($validated_path);
        echo '</body></html>';
    } else {
        header("HTTP/1.0 404 Not Found");
        die('ERROR: File not found or not readable.');
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $_SESSION['op_log'] = [];
    if ($action === 'delete_files') {
        $files_to_delete = $_POST['files_to_delete'] ?? [];
        $deleted_count = 0; $failed_count = 0;
        foreach ($files_to_delete as $b64_path) {
            $file_path = base64_decode($b64_path);
            $validated_path = validate_path($file_path);
            if ($validated_path && is_file($validated_path) && @unlink($validated_path)) {
                $deleted_count++;
            } else {
                $_SESSION['op_log'][] = "Failed to delete: " . htmlspecialchars($validated_path);
                $failed_count++;
            }
        }
        $_SESSION['flash_message'] = "Delete operation: $deleted_count succeeded, $failed_count failed.";
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
    if ($action === 'create_htaccess') {
        $dir_path = $_POST['dir_path'] ?? '';
        $validated_dir = validate_path($dir_path);
        if ($validated_dir && is_dir($validated_dir)) {
            $htaccess_path = $validated_dir . '/.htaccess';
            $whitelist_files = array_filter(array_map('trim', explode(',', $_POST['whitelist_files'] ?? '')));
            $rewrite_cond = '';
            if (!empty($whitelist_files)) {
                $escaped_files = array_map(function($file) { return preg_quote($file, '/'); }, $whitelist_files);
                $rewrite_cond = "    RewriteCond %{REQUEST_URI} !/(" . implode('|', $escaped_files) . ")$ [NC]\n";
            }
            $htaccess_content = "<IfModule mod_rewrite.c>\n    RewriteEngine On\n{$rewrite_cond}    RewriteRule \.(php|phtml|pht|php3|php4|php5|php7|phar|sh|pl|py|cgi)$ - [F,L]\n</IfModule>\n\n<Files .htaccess>\n    Require all denied\n</Files>";
            if (@file_put_contents($htaccess_path, "\n# -- SECURED BY ANALYZER --\n" . $htaccess_content, FILE_APPEND)) {
                $_SESSION['flash_message'] = "Success: .htaccess rules added to " . htmlspecialchars($htaccess_path);
            } else {
                $_SESSION['flash_message'] = "Error: Could not write to .htaccess in the specified directory.";
            }
        } else {
            $_SESSION['flash_message'] = "Error: Invalid directory specified.";
        }
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}
$scan_in_progress = ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['start_scan']));
$view_processes_request = ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'view_processes');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Security Analyzer v8.0</title>
    <style>
        :root {
            --bg-color: #f8f9fa; --text-color: #212529; --primary-color: #0d6efd; --border-color: #dee2e6;
            --card-bg: #fff; --red-color: #dc3545; --yellow-color: #ffc107; --green-color: #198754; --muted-color: #6c757d;
        }
        body { background-color: var(--bg-color); color: var(--text-color); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; padding: 2rem; font-size: 16px; line-height: 1.5; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1, h2 { border-bottom: 1px solid var(--border-color); padding-bottom: 0.5rem; }
        h1 { text-align: center; border-bottom: none; }
        .author { font-size: 0.8rem; color: var(--muted-color); text-align: center; margin-top: -1rem; margin-bottom: 2rem; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 2rem; }
        .card { background-color: var(--card-bg); border: 1px solid var(--border-color); border-radius: 0.375rem; padding: 1.5rem; box-shadow: 0 0.125rem 0.25rem rgba(0,0,0,.075); }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; font-weight: 600; }
        .form-control { display: block; width: 100%; padding: 0.5rem 1rem; font-size: 1rem; font-family: 'SFMono-Regular', Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; color: var(--text-color); background-color: var(--card-bg); border: 1px solid var(--border-color); border-radius: 0.375rem; transition: border-color .15s ease-in-out,box-shadow .15s ease-in-out; box-sizing: border-box;}
        .form-text { font-size: .875em; color: var(--muted-color); }
        .btn { display: inline-block; font-weight: 600; line-height: 1.5; color: #fff; text-align: center; cursor: pointer; user-select: none; background-color: var(--primary-color); border: 1px solid var(--primary-color); padding: 0.5rem 1rem; font-size: 1rem; border-radius: 0.375rem; transition: all .15s ease-in-out; }
        .btn:hover { background-color: #0b5ed7; }
        .btn-danger { background-color: var(--red-color); border-color: var(--red-color); } .btn-danger:hover { background-color: #bb2d3b; }
        .btn-warning { background-color: var(--yellow-color); border-color: var(--yellow-color); color: #000; } .btn-warning:hover { background-color: #ffca2c; }
        .btn-subtle { background-color: #6c757d; border-color: #6c757d; } .btn-subtle:hover { background-color: #5c636a; }
        .flash { padding: 1rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: 0.375rem; }
        .flash-success { color: #0f5132; background-color: #d1e7dd; border-color: #badbcc; }
        .flash-danger { color: #842029; background-color: #f8d7da; border-color: #f5c2c7; }
        .results-list { list-style: none; padding: 0; }
        .results-list li { border-radius: 4px; margin-bottom: 1rem; padding: 1rem; display: flex; flex-wrap: wrap; gap: 1rem; }
        .severity-Suspicious { border-left: 5px solid var(--yellow-color); background-color: #fff9e8; }
        .severity-High-Risk { border-left: 5px solid var(--red-color); background-color: #fdeeee; }
        .results-list .file-details { flex-grow: 1; word-break: break-all; }
        .results-list .file-path { font-weight: 600; }
        .results-list .reason { font-size: 0.9rem; font-weight: 600; }
        .reason-High-Risk { color: var(--red-color); } .reason-Suspicious { color: #9a7206; }
        .results-list .meta-info { font-size: 0.85rem; color: var(--muted-color); display: flex; gap: 1.5rem; margin-top: 0.5rem; }
        pre.process-list { background-color: #212529; color: #dcdcdc; padding: 1rem; border-radius: 4px; max-height: 400px; overflow-y: auto; font-size: 14px; }
        pre.process-list .highlight { color: var(--yellow-color); font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Analyzer <span style="color:var(--primary-color)">v8.0</span></h1>
        <p class="author">by z3r0-team! x #CianjurHacktivist</p>

        <?php if (isset($_SESSION['flash_message'])): ?>
            <div class="flash <?php echo strpos(strtolower($_SESSION['flash_message']), 'error') !== false ? 'flash-danger' : 'flash-success'; ?>"><?php echo $_SESSION['flash_message']; unset($_SESSION['flash_message']); ?></div>
        <?php endif; ?>

        <div class="dashboard">
            <div class="card">
                <h2>🔍 Start New Scan</h2>
                <form method="post" action=""><input type="hidden" name="start_scan" value="1"><div class="form-group"><label for="scan_dir">Target Directory</label><input type="text" id="scan_dir" name="scan_dir" class="form-control" value="<?php echo htmlspecialchars(realpath('.')); ?>"></div><button type="submit" class="btn">Initiate Scan</button></form>
            </div>
            <div class="card">
                <h2>🛡️ Secure Directory</h2>
                <form method="post" action=""><input type="hidden" name="action" value="create_htaccess"><div class="form-group"><label for="dir_path">Directory to protect</label><input type="text" id="dir_path" name="dir_path" class="form-control" placeholder="/path/to/uploads"></div><div class="form-group"><label for="whitelist_files">Whitelist Files (Optional)</label><input type="text" id="whitelist_files" name="whitelist_files" class="form-control" placeholder="index.php, admin-ajax.php"><div class="form-text">Pisahkan nama file dengan koma.</div></div><button type="submit" class="btn">Create .htaccess</button></form>
            </div>
            <div class="card">
                <h2>⚙️ System Processes</h2>
                <form method="post" action=""><input type="hidden" name="action" value="view_processes"><button type="submit" class="btn btn-warning">View Running Processes</button></form>
            </div>
        </div>

        <?php if ($view_processes_request): ?>
            <div class="card" style="margin-top: 2rem;"><h2>Running Processes</h2><pre class="process-list"><?php echo highlight_processes(get_process_list()); ?></pre></div>
        <?php endif; ?>

        <?php if ($scan_in_progress): ?>
        <div class="card" style="margin-top: 2rem;">
            <h2>Scan Results</h2>
            <form method="post" action="">
                <input type="hidden" name="action" value="delete_files">
                <ul class="results-list">
                    <?php
                    $scan_path = validate_path($_POST['scan_dir']);
                    $infected_files_count = 0;
                    if ($scan_path) {
                        try {
                            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($scan_path, FilesystemIterator::UNIX_PATHS), RecursiveIteratorIterator::SELF_FIRST);
                            foreach ($iterator as $path => $file) {
                                if ($file->getBasename() === '.' || $file->getBasename() === '..') continue;
                                if (!$file->isReadable()) { if (!make_accessible($path, $_SESSION['op_log'])) continue; }
                                if ($file->isFile() && in_array(strtolower($file->getExtension()), $file_extensions)) {
                                    $file_content = @file_get_contents($path);
                                    if ($file_content === false) continue;
                                    $findings = [];
                                    foreach ($signatures as $severity => $categories) {
                                        foreach ($categories as $category => $patterns) {
                                            foreach ($patterns as $pattern) { if (preg_match($pattern, $file_content)) { $findings[$severity][] = $category; } }
                                        }
                                    }
                                    if (!empty($findings)) {
                                        $infected_files_count++;
                                        $b64_path = base64_encode($path);
                                        $highest_severity = isset($findings['High-Risk']) ? 'High-Risk' : 'Suspicious';
                    ?>
                    <li class="severity-<?php echo $highest_severity; ?>">
                        <input type="checkbox" name="files_to_delete[]" value="<?php echo $b64_path; ?>" style="margin: 0.5rem 1rem 0 0; transform: scale(1.5);">
                        <div class="file-details">
                            <div class="file-path"><?php echo htmlspecialchars($path); ?></div>
                            <div class="reason reason-<?php echo $highest_severity; ?>">[<?php echo strtoupper($highest_severity); ?>] Found in categories: <?php echo htmlspecialchars(implode(', ', array_unique(call_user_func_array('array_merge', $findings)))); ?></div>
                            <div class="meta-info">
                                <span>📅 Modified: <?php echo date("Y-m-d H:i:s", $file->getMTime()); ?></span>
                                <span>💾 Size: <?php echo format_size($file->getSize()); ?></span>
                            </div>
                        </div>
                        <a href="?action=view_source&path=<?php echo $b64_path; ?>" target="_blank" class="btn btn-subtle">👀 View Source</a>
                    </li>
                    <?php
                                    }
                                }
                            }
                        } catch (Exception $e) { $_SESSION['flash_message'] = "An error occurred: " . $e->getMessage(); }
                    } else { $_SESSION['flash_message'] = "Error: Invalid scan path."; }
                    if ($infected_files_count === 0) { echo "<p>✅ No suspicious files found.</p>"; }
                    ?>
                </ul>
                <?php if ($infected_files_count > 0): ?>
                <button type="submit" class="btn btn-danger" onclick="return confirm('Are you sure? This action cannot be undone.');">🗑️ Delete Selected Files</button>
                <?php endif; ?>
            </form>
        </div>
        <?php endif; ?>
    </div>
</body>
</html>
