<?php
header('X-Robots-Tag: noindex, nofollow', true);
@set_time_limit(0);
@ignore_user_abort(true);
date_default_timezone_set('Asia/Jakarta');

$file_extensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'htaccess'];
$log_filename = 'ngapain.txt';

$malware_signatures = [
    'Shell/Backdoor Umum' => [
        '/\b(c99|r57|b374k|wso|webshell|IndoXploit|An0n_ শেল)\b/i',
        '/\b(shell_exec|passthru|proc_open|system|popen|pcntl_exec)\s*\(/i',
        '/(?<![a-z0-9_])eval\s*\(\s*\$(GET|POST|REQUEST|COOKIE)/i',
        '/\b(FilesMan|p0wny-shell|file-manager)\b/i',
        '/@ini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']0["\']\s*\)/i',
    ],
    'Kode Terenkripsi/Obfuscated' => [
        '/\beval\s*\(\s*base64_decode\s*\(/i',
        '/\beval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(/i',
        '/\beval\s*\(\s*gzuncompress\s*\(\s*base64_decode\s*\(/i',
        '/\beval\s*\(\s*str_rot13\s*\(\s*base64_decode\s*\(/i',
        '/\$\w+\s*=\s*"\w{300,}"/i',
        '/\b(chr|ord)\s*\(\d+\)\s*\.\s*\b(chr|ord)\s*\(\d+\)/i',
        '/\$[0OoIli1]+\s*=\s*\$[0OoIli1]\s*\(/i',
    ],
    'Eksekusi Kode Jarak Jauh' => [
        '/\b(curl_exec|fsockopen|pfsockopen|stream_socket_client)\s*\(/i',
        '/include\s*\(\s*\$_GET/i',
        '/require\s*\(\s*\$_GET/i',
        '/file_get_contents\s*\(\s*["\'](http|ftp)s?:\/\//i',
        '/\b(move_uploaded_file)\s*\(\s*\$_FILES\[.+\]\[\'tmp_name\'\]\s*,\s*".+\.php"\s*\)/i',
    ],
    'Potensi Spammer' => [
        '/\b(mail|imap_open)\s*\(/i',
        '/\$message\s*=\s*".*MIME-Version:/is',
        '/\b(mass mail|mailer|spam)\b/i',
    ],
    'Pencurian Informasi' => [
        '/fopen\s*\(\s*["\'].*wp-config\.php["\']\s*,\s*["\']r["\']\s*\)/i',
        '/file_get_contents\s*\(\s*["\'].*\/etc\/passwd["\']\s*\)/i',
        '/\b(uname\s*-a|pwd)\b/i',
    ],
    '.htaccess Berbahaya' => [
        '/RewriteRule\s+.*\s+http:\/\//i',
        '/AddType\s+application\/x-httpd-php\s+\.jpg/i',
        '/php_value\s+auto_prepend_file/i',
    ]
];

function scan_file($file_path, $signatures) {
    $content = @file_get_contents($file_path);
    if ($content === false) return [];
    $findings = [];
    foreach ($signatures as $category => $patterns) {
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                $findings[] = $category;
            }
        }
    }
    return array_unique($findings);
}

function log_finding($log_file, $file_path, $reasons) {
    $date = date('Y-m-d H:i:s');
    $reason_str = implode(', ', $reasons);
    $log_entry = "[$date] :: DETECTION <$reason_str> :: FILE <$file_path>\n";
    @file_put_contents($log_file, $log_entry, FILE_APPEND);
}

function validate_scan_path($user_path, &$error_message) {
    $default_path = realpath('.');
    if (empty($user_path)) return $default_path;
    $real_user_path = realpath($user_path);
    $doc_root = realpath($_SERVER['DOCUMENT_ROOT']);
    if ($real_user_path === false) {
        $error_message = 'ERROR: PATH NOT FOUND. Using current directory.';
        return $default_path;
    }
    if ($doc_root && strpos($real_user_path, $doc_root) !== 0) {
        $error_message = 'ERROR: PATH OUTSIDE ALLOWED SCOPE. Using current directory.';
        return $default_path;
    }
    return $real_user_path;
}

$scan_in_progress = ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['start_scan']));
$error_message = '';
$scan_path = '';

if ($scan_in_progress) {
    $scan_path = validate_scan_path($_POST['scan_dir'], $error_message);
    if (is_writable($log_filename) || !file_exists($log_filename)) {
        $header = "## z3r0-scan LOG INITIALIZED: " . date('Y-m-d H:i:s') . " ##\n";
        $header .= "## TARGET_DIRECTORY: " . $scan_path . " ##\n";
        $header .= "--------------------------------------------------------\n";
        @file_put_contents($log_filename, $header, FILE_APPEND);
    } else {
        $error_message = "FATAL ERROR: CANNOT WRITE TO LOG FILE '$log_filename'. CHECK PERMISSIONS.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Z3R0-SCAN v3.0</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=VT323&display=swap" rel="stylesheet">
    <style>
        @keyframes scanline {
            0% { background-position: 0 0; }
            100% { background-position: 0 100%; }
        }
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0; }
        }
        body {
            background-color: #000;
            color: #0f0;
            font-family: 'VT323', monospace;
            font-size: 18px;
            margin: 0;
            padding: 20px;
            text-shadow: 0 0 3px #0f0;
        }
        body::before {
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
            background-size: 100% 3px, 4px 100%;
            z-index: 2;
            pointer-events: none;
            animation: scanline 10s linear infinite;
        }
        .container {
            border: 2px solid #0f0;
            box-shadow: 0 0 10px #0f0, inset 0 0 10px #0f0;
            padding: 20px;
            position: relative;
            z-index: 1;
        }
        h1, h2 {
            text-align: center;
            margin: 10px 0 20px 0;
        }
        .cursor {
            animation: blink 1s step-end infinite;
            background-color: #0f0;
            display: inline-block;
            width: 10px;
            height: 1.2em;
            margin-left: 5px;
            box-shadow: 0 0 5px #0f0;
        }
        .alert {
            border: 1px solid #ff0000;
            color: #ff0000;
            padding: 10px;
            margin-bottom: 20px;
            text-align: center;
            text-transform: uppercase;
        }
        .form-group label {
            display: block;
            margin-bottom: 10px;
        }
        .form-group input {
            background-color: #050505;
            border: 1px solid #0f0;
            color: #0f0;
            font-family: 'VT323', monospace;
            font-size: 18px;
            padding: 10px;
            width: 100%;
            box-sizing: border-box;
            text-shadow: 0 0 3px #0f0;
        }
        input:focus {
            outline: none;
            box-shadow: 0 0 8px #0f0;
        }
        button {
            background-color: #090;
            border: 1px solid #0f0;
            color: #000;
            font-family: 'VT323', monospace;
            font-size: 20px;
            padding: 15px;
            width: 100%;
            text-transform: uppercase;
            cursor: pointer;
            margin-top: 10px;
        }
        button:hover {
            background-color: #0f0;
            color: #000;
        }
        .scan-log {
            border: 1px solid #0f0;
            height: 300px;
            overflow-y: auto;
            padding: 10px;
            margin-top: 20px;
            background-color: rgba(0, 255, 0, 0.05);
        }
        .log-entry { margin-bottom: 5px; }
        .log-entry .file { color: #fff; }
        .log-entry .reason { color: #f00; text-transform: uppercase; }
        .summary {
            border: 1px solid #0f0;
            padding: 15px;
            margin-top: 20px;
            background-color: #050505;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SYSTEM INTEGRITY ANALYZER v3.0<span class="cursor"></span></h1>
        <div class="footer">AUTHOR: z3r0-team! x #CianjurHacktivist</div>
        
        <div class="alert">SECURITY_DIRECTIVE: DELETE THIS UTILITY AND ALL LOGS AFTER USE.</div>

        <?php if ($error_message): ?>
            <div class="alert"><?php echo htmlspecialchars($error_message); ?></div>
        <?php endif; ?>

        <?php if ($scan_in_progress): ?>
            <h2>LOG_ANALYSIS://<span class="cursor"></span></h2>
            <p>>_ SCANNING_TARGET: <?php echo htmlspecialchars($scan_path); ?></p>
            <p>>_ LOG_OUTPUT: <a href="<?php echo htmlspecialchars($log_filename); ?>" target="_blank" style="color:#0f0;"><?php echo htmlspecialchars($log_filename); ?></a></p>
            <div class="scan-log">
                <?php
                $total_files_scanned = 0;
                $infected_files_count = 0;
                
                if (file_exists($scan_path)) {
                    $iterator = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($scan_path, RecursiveDirectoryIterator::SKIP_DOTS),
                        RecursiveIteratorIterator::SELF_FIRST,
                        RecursiveIteratorIterator::CATCH_GET_CHILD
                    );

                    ob_flush(); flush();

                    foreach ($iterator as $file) {
                        try {
                            if ($file->isFile() && in_array(strtolower($file->getExtension()), $file_extensions)) {
                                $total_files_scanned++;
                                $file_path = $file->getRealPath();
                                
                                $signatures_to_use = ($file->getExtension() == 'htaccess') 
                                    ? ['.htaccess Berbahaya' => $malware_signatures['.htaccess Berbahaya']] 
                                    : array_diff_key($malware_signatures, array_flip(['.htaccess Berbahaya']));
                                
                                $findings = scan_file($file_path, $signatures_to_use);

                                if (!empty($findings)) {
                                    $infected_files_count++;
                                    log_finding($log_filename, $file_path, $findings);
                                    
                                    echo '<div class="log-entry">';
                                    echo '  <span class="reason">[!] ANOMALY DETECTED</span> <span class="file">' . htmlspecialchars($file_path) . '</span>';
                                    echo '</div>';
                                }
                                
                                if ($total_files_scanned % 50 == 0) {
                                    echo ''; ob_flush(); flush();
                                }
                            }
                        } catch (UnexpectedValueException $e) { /* ignore unreadable files */ }
                    }
                }
                ?>
                 <div class="log-entry">>> SCAN_COMPLETE<span class="cursor"></span></div>
            </div>

            <div class="summary">
                <h3>>_ MISSION_SUMMARY:</h3>
                <p>TOTAL_FILES_ANALYZED: <?php echo $total_files_scanned; ?></p>
                <p>ANOMALIES_DETECTED: <?php echo $infected_files_count; ?></p>
                <?php if ($infected_files_count > 0): ?>
                    <p style="color:#ff0000;">ACTION_REQUIRED: Review log file `<?php echo htmlspecialchars($log_filename); ?>` immediately.</p>
                <?php else: ?>
                    <p>SYSTEM_STATUS: ALL CLEAR. NO ANOMALIES DETECTED.</p>
                <?php endif; ?>
            </div>

        <?php else: ?>
            <form method="post" action="">
                <div class="form-group">
                    <label for="scan_dir">> SET TARGET_DIRECTORY:</label>
                    <input type="text" id="scan_dir" name="scan_dir" value="<?php echo htmlspecialchars(realpath('.')); ?>">
                </div>
                <button type="submit" name="start_scan">[ INITIATE SCAN ]</button>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>
