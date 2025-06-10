<?php
session_start();
header('X-Robots-Tag: noindex, nofollow', true);
@set_time_limit(0);
@ignore_user_abort(true);
date_default_timezone_set('Asia/Jakarta');

$file_extensions = ['php', 'phtml', 'pht', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'ini', 'htaccess'];
$signatures = [
    'Shell/Backdoor' => ['/\b(c99|r57|b374k|wso|webshell|IndoXploit)\b/i', '/\b(shell_exec|passthru|proc_open|system|popen)\s*\(/i', '/\b(FilesMan|p0wny-shell)\b/i'],
    'Code Obfuscation' => ['/\beval\s*\(\s*base64_decode\s*\(/i', '/\beval\s*\(\s*gzinflate\s*\(/i', '/\$\w+\s*=\s*"\w{300,}"/i', '/\b(chr|ord)\s*\(\d+\)\s*\.\s*\b(chr|ord)\s*\(\d+\)/i'],
    'Remote Execution' => ['/\b(curl_exec|fsockopen|pfsockopen)\s*\(/i', '/(include|require)\s*\(\s*\$_(GET|POST|REQUEST)/i', '/file_get_contents\s*\(\s*["\'](http|ftp)s?:\/\//i'],
    'WordPress Specific' => ['/fopen\s*\(\s*["\'].*wp-config\.php["\']\s*,\s*["\']r["\']\s*\)/i', '/php_value\s+auto_prepend_file/i', '/AddType\s+application\/x-httpd-php\s+\.jpg/i']
];

function validate_path($path) {
    $real_path = realpath(trim($path));
    $doc_root = realpath($_SERVER['DOCUMENT_ROOT']);
    if ($real_path === false || strpos($real_path, $doc_root) !== 0) return false;
    return $real_path;
}

function make_accessible(&$path, &$log) {
    if (is_readable($path)) return true;
    $perms = is_dir($path) ? 0755 : 0644;
    if (@chmod($path, $perms)) {
        clearstatcache();
        if (is_readable($path)) {
            $log[] = "Permissions adjusted for: " . htmlspecialchars($path);
            return true;
        }
    }
    $log[] = "Failed to adjust permissions for: " . htmlspecialchars($path);
    return false;
}

function format_size($bytes) {
    if ($bytes >= 1048576) return number_format($bytes / 1048576, 2) . ' MB';
    if ($bytes >= 1024) return number_format($bytes / 1024, 2) . ' KB';
    return $bytes . ' bytes';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $_SESSION['op_log'] = [];

    if ($action === 'view_file') {
        header('Content-Type: text/plain');
        $file_path = base64_decode($_POST['path'] ?? '');
        $validated_path = validate_path($file_path);
        if (!$validated_path || !is_readable($validated_path)) die('ERROR: File not found or not readable.');
        echo file_get_contents($validated_path);
        exit;
    }

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

            $htaccess_content = <<<HTACCESS
<IfModule mod_rewrite.c>
    RewriteEngine On
{$rewrite_cond}    RewriteRule \.(php|phtml|pht|php3|php4|php5|php7|phar|sh|pl|py|cgi)$ - [F,L]
</IfModule>

<Files .htaccess>
    Require all denied
</Files>
HTACCESS;
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Security Analyzer v6.1</title>
    <style>
        :root {
            --bg-color: #f8f9fa; --text-color: #212529; --primary-color: #0d6efd; --border-color: #dee2e6;
            --card-bg: #fff; --red-color: #dc3545; --green-color: #198754; --muted-color: #6c757d;
        }
        body {
            background-color: var(--bg-color); color: var(--text-color); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0; padding: 2rem; font-size: 16px; line-height: 1.5;
        }
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
        .btn-danger { background-color: var(--red-color); border-color: var(--red-color); }
        .btn-danger:hover { background-color: #bb2d3b; }
        .btn-subtle { background-color: #6c757d; border-color: #6c757d; } .btn-subtle:hover { background-color: #5c636a; }
        .flash { padding: 1rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: 0.375rem; }
        .flash-success { color: #0f5132; background-color: #d1e7dd; border-color: #badbcc; }
        .flash-danger { color: #842029; background-color: #f8d7da; border-color: #f5c2c7; }
        .results-list { list-style: none; padding: 0; }
        .results-list li { background-color: var(--card-bg); border: 1px solid var(--border-color); border-radius: 4px; margin-bottom: 1rem; padding: 1rem; display: flex; flex-wrap: wrap; gap: 1rem; }
        .results-list .file-details { flex-grow: 1; word-break: break-all; }
        .results-list .file-path { font-weight: 600; }
        .results-list .reason { color: var(--red-color); font-size: 0.9rem; font-weight: 600; }
        .results-list .meta-info { font-size: 0.85rem; color: var(--muted-color); display: flex; gap: 1.5rem; margin-top: 0.5rem; }
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.5); }
        .modal-content { position: relative; background-color: #fefefe; margin: 5% auto; padding: 20px; border: 1px solid #888; width: 80%; border-radius: 0.3rem; }
        .modal-body pre { background-color: #f8f9fa; padding: 1rem; border-radius: 0.3rem; max-height: 70vh; overflow-y: auto; font-family: 'SFMono-Regular', Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Analyzer <span style="color:var(--primary-color)">v6.1</span></h1>
        <p class="author">by z3r0-team! x #CianjurHacktivist</p>

        <?php if (isset($_SESSION['flash_message'])): ?>
            <div class="flash <?php echo strpos(strtolower($_SESSION['flash_message']), 'error') !== false ? 'flash-danger' : 'flash-success'; ?>"><?php echo $_SESSION['flash_message']; unset($_SESSION['flash_message']); ?></div>
        <?php endif; ?>

        <div class="dashboard">
            <div class="card">
                <h2>🔍 Start New Scan</h2>
                <form method="post" action="">
                    <input type="hidden" name="start_scan" value="1">
                    <div class="form-group">
                        <label for="scan_dir">Target Directory</label>
                        <input type="text" id="scan_dir" name="scan_dir" class="form-control" value="<?php echo htmlspecialchars(realpath('.')); ?>">
                    </div>
                    <button type="submit" class="btn">Initiate Scan</button>
                </form>
            </div>
            <div class="card">
                <h2>🛡️ Secure Directory</h2>
                <form method="post" action="">
                    <input type="hidden" name="action" value="create_htaccess">
                    <div class="form-group">
                        <label for="dir_path">Directory to protect</label>
                        <input type="text" id="dir_path" name="dir_path" class="form-control" placeholder="/home/user/public_html/uploads">
                    </div>
                    <div class="form-group">
                        <label for="whitelist_files">Whitelist Files (Optional)</label>
                        <input type="text" id="whitelist_files" name="whitelist_files" class="form-control" placeholder="index.php, admin-ajax.php">
                        <div class="form-text">Pisahkan nama file dengan koma.</div>
                    </div>
                    <button type="submit" class="btn">Create .htaccess</button>
                </form>
            </div>
        </div>

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
                                    foreach ($signatures as $category => $patterns) {
                                        foreach ($patterns as $pattern) { if (preg_match($pattern, $file_content)) { $findings[] = $category; } }
                                    }
                                    if (!empty($findings)) {
                                        $infected_files_count++;
                                        $b64_path = base64_encode($path);
                    ?>
                    <li>
                        <input type="checkbox" name="files_to_delete[]" value="<?php echo $b64_path; ?>" style="margin: 0.5rem 1rem 0 0; transform: scale(1.5);">
                        <div class="file-details">
                            <div class="file-path"><?php echo htmlspecialchars($path); ?></div>
                            <div class="reason"><?php echo htmlspecialchars(implode(', ', array_unique($findings))); ?></div>
                            <div class="meta-info">
                                <span>📅 Modified: <?php echo date("Y-m-d H:i:s", $file->getMTime()); ?></span>
                                <span>💾 Size: <?php echo format_size($file->getSize()); ?></span>
                            </div>
                        </div>
                        <button type="button" class="btn btn-subtle view-file-btn" data-path="<?php echo $b64_path; ?>">👀 View</button>
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

    <div id="fileViewerModal" class="modal">
        <div class="modal-content">
            <span style="float:right; font-size: 28px; font-weight: bold; cursor: pointer;" onclick="document.getElementById('fileViewerModal').style.display='none'">&times;</span>
            <h2>File Viewer</h2>
            <div class="modal-body"><pre id="fileContent"></pre></div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const modal = document.getElementById('fileViewerModal');
            const fileContentEl = document.getElementById('fileContent');
            document.querySelectorAll('.view-file-btn').forEach(button => {
                button.addEventListener('click', function() {
                    fileContentEl.textContent = 'Loading...';
                    modal.style.display = 'block';
                    fetch(window.location.href, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                        body: 'action=view_file&path=' + this.dataset.path
                    }).then(r => r.text()).then(text => fileContentEl.textContent = text)
                      .catch(e => fileContentEl.textContent = 'Error: ' + e);
                });
            });
            window.onclick = (event) => { if (event.target == modal) { modal.style.display = 'none'; } };
        });
    </script>
</body>
</html>
