<?php
// scanner.php

// Inisialisasi target dir default dari working directory PHP saat ini
$defaultDir = getcwd();

function scanDirForKeywords($dir, &$results, $depth = 0, $maxDepth = 10) {
    $blacklistLicense = "@license http://opensource.org";
    $keywords = [
        'base64_decode', 'Webshell', 'error_reporting', 'Priv8', '<?=', '));?>',
        '/^data:.*;base64,/', '@license http://opensource.org'
    ];

    if ($depth > $maxDepth) return;

    $extPattern = '/\.(php|phtml|php5|php7|shtml)$/i';

    if (!is_dir($dir)) return;

    $files = @scandir($dir);
    if ($files === false) return;

    foreach ($files as $file) {
        if ($file === '.' || $file === '..') continue;

        $fullPath = $dir . DIRECTORY_SEPARATOR . $file;

        if (is_dir($fullPath)) {
            scanDirForKeywords($fullPath, $results, $depth + 1, $maxDepth);
        } else {
            if (!preg_match($extPattern, $file)) continue;

            $content = @file_get_contents($fullPath);
            if ($content === false) continue;

            // Skip if blacklist license is present
            if (stripos($content, $blacklistLicense) !== false) continue;

            $foundKeys = [];
            foreach ($keywords as $key) {
                if ($key === '/^data:.*;base64,/') {
                    // regex match
                    if (preg_match($key, $content)) {
                        $foundKeys[] = 'data:base64';
                    }
                } else {
                    if (stripos($content, $key) !== false) {
                        $foundKeys[] = $key;
                    }
                }
            }

            if (!empty($foundKeys)) {
                // Simpan path relative dari root scan
                $results[$fullPath] = $foundKeys;
            }
        }
    }
}

function safePath($path) {
    // Normalize path for JS output and HTML attributes
    return htmlspecialchars($path, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// Handle AJAX actions
if (isset($_GET['action'])) {
    $action = $_GET['action'];

    if ($action === 'scan') {
        $dir = $_GET['dir'] ?? $defaultDir;
        if (!is_dir($dir)) {
            echo json_encode(['error' => 'Invalid directory']);
            exit;
        }
        $results = [];
        scanDirForKeywords($dir, $results);

        // Return relative file names for display
        echo json_encode($results);
        exit;
    }

    if ($action === 'viewfile') {
        $file = $_GET['file'] ?? '';
        if (!file_exists($file) || !is_file($file)) {
            echo json_encode(['error' => 'File not found']);
            exit;
        }
        $content = file_get_contents($file);
        // Return raw content (PHP, no escaping)
        echo json_encode(['content' => $content]);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_GET['action'] ?? '';

    if ($action === 'deletefile') {
        $file = $_POST['file'] ?? '';
        if (!file_exists($file) || !is_file($file)) {
            echo json_encode(['error' => 'File not found']);
            exit;
        }
        // Try to chmod 0644 before deleting
        @chmod($file, 0644);
        if (@unlink($file)) {
            echo json_encode(['success' => 'File deleted']);
        } else {
            echo json_encode(['error' => 'Failed to delete file']);
        }
        exit;
    }

    if ($action === 'renamefile') {
        $file = $_POST['file'] ?? '';
        $newname = $_POST['newname'] ?? '';
        if (!file_exists($file) || !is_file($file)) {
            echo json_encode(['error' => 'File not found']);
            exit;
        }
        $dir = dirname($file);
        $newpath = $dir . DIRECTORY_SEPARATOR . basename($newname);
        if (file_exists($newpath)) {
            echo json_encode(['error' => 'File with new name already exists']);
            exit;
        }
        // Try to chmod 0644 before renaming
        @chmod($file, 0644);
        if (@rename($file, $newpath)) {
            echo json_encode(['success' => 'File renamed']);
        } else {
            echo json_encode(['error' => 'Failed to rename file']);
        }
        exit;
    }
}

// ----------------- HTML + JS + CSS below -----------------
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>PHP Malware Scanner - binyourbae #CianjurHacktivist</title>

<!-- Google Fonts Retro -->
<link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap" rel="stylesheet" />

<style>
  /* Reset */
  * {
    box-sizing: border-box;
  }
  body {
    margin: 0;
    background: #04190f;
    color: #00ff00;
    font-family: 'Press Start 2P', cursive, monospace;
    font-size: 12px;
    line-height: 1.3;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }
  header {
    background: #002b08;
    padding: 1rem 1.5rem;
    border-bottom: 2px solid #00ff00;
    text-align: center;
    user-select: none;
    letter-spacing: 0.15em;
  }
  header h1 {
    margin: 0;
    font-size: 1.4rem;
    color: #00ff00;
    text-shadow:
       0 0 5px #00ff00,
       0 0 10px #00ff00,
       0 0 20px #00ff00;
  }
  .breadcrumb {
    background: #003214;
    padding: 0.5rem 1rem;
    border-bottom: 2px solid #00ff00;
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
  .breadcrumb button.folder-btn {
    background: transparent;
    border: 1px solid #00ff00;
    color: #00ff00;
    padding: 6px 10px;
    cursor: pointer;
    font-size: 9px;
    letter-spacing: 0.1em;
    transition: background 0.3s, color 0.3s;
  }
  .breadcrumb button.folder-btn:hover {
    background: #00ff00;
    color: #003214;
  }
  main {
    flex: 1;
    padding: 1rem 1.5rem;
    overflow-x: auto;
  }
  button#btnScan {
    font-family: 'Press Start 2P', cursive, monospace;
    font-size: 10px;
    color: #04190f;
    background: #00ff00;
    border: 2px solid #00ff00;
    padding: 8px 18px;
    cursor: pointer;
    margin-bottom: 1rem;
    display: block;
    margin-left: auto;
    margin-right: auto;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    box-shadow:
      0 0 15px #00ff00,
      inset 0 0 5px #003214;
    transition: background 0.3s, color 0.3s, box-shadow 0.3s;
  }
  button#btnScan:hover:not(:disabled) {
    background: #003214;
    color: #00ff00;
    box-shadow:
      0 0 30px #00ff00,
      inset 0 0 10px #00ff00;
  }
  button#btnScan:disabled {
    background: #006622;
    cursor: wait;
    box-shadow: none;
    color: #00440f;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 11px;
    user-select: text;
  }
  thead tr {
    background: #003214;
    border-bottom: 2px solid #00ff00;
  }
  thead th {
    padding: 10px 8px;
    text-align: left;
    color: #00ff00;
    text-shadow:
      0 0 3px #00ff00;
    letter-spacing: 0.1em;
  }
  tbody tr:nth-child(odd) {
    background: #012e0b;
  }
  tbody tr:nth-child(even) {
    background: #021f07;
  }
  tbody td {
    padding: 8px 10px;
    border-right: 1px solid #00440f;
    color: #00ff00;
    white-space: nowrap;
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
    cursor: default;
  }
  tbody td.file-name {
    cursor: pointer;
    text-decoration: underline;
  }
  tbody td.file-name:hover {
    color: #a0ffa0;
  }
  tbody td.actions {
    display: flex;
    gap: 0.5rem;
  }
  button.action-btn {
    font-family: 'Press Start 2P', cursive, monospace;
    font-size: 8px;
    background: transparent;
    border: 1px solid #00ff00;
    color: #00ff00;
    padding: 6px 8px;
    cursor: pointer;
    transition: background 0.3s, color 0.3s;
  }
  button.action-btn:hover {
    background: #00ff00;
    color: #04190f;
    box-shadow: 0 0 8px #00ff00;
  }
  #popup {
    position: fixed;
    top: 10%;
    left: 50%;
    transform: translateX(-50%);
    width: 90vw;
    max-width: 900px;
    max-height: 80vh;
    background: #001b03;
    border: 3px solid #00ff00;
    box-shadow:
      0 0 15px #00ff00;
    padding: 1rem 1.2rem 1.5rem 1.2rem;
    overflow-y: auto;
    font-size: 9px;
    font-family: 'Courier New', Courier, monospace;
    white-space: pre-wrap;
    z-index: 9999;
    display: none;
  }
  #popup h2 {
    margin: 0 0 0.5rem 0;
    font-size: 12px;
    text-shadow: 0 0 5px #00ff00;
  }
  #popup pre {
    color: #00ff00;
    user-select: text;
  }
  #popup .close-btn {
    position: absolute;
    right: 8px;
    top: 8px;
    font-size: 18px;
    font-weight: bold;
    color: #00ff00;
    background: transparent;
    border: none;
    cursor: pointer;
    transition: color 0.3s;
  }
  #popup .close-btn:hover {
    color: #a0ffa0;
  }
  #footer {
    text-align: center;
    padding: 0.7rem 0;
    font-size: 9px;
    color: #00440f;
    background: #001b03;
    border-top: 2px solid #00ff00;
    font-family: 'Press Start 2P', cursive, monospace;
    user-select: none;
  }
  /* Responsive */
  @media (max-width: 600px) {
    tbody td {
      font-size: 9px;
      max-width: 140px;
      white-space: normal;
      word-break: break-word;
    }
    button#btnScan {
      font-size: 8px;
      padding: 6px 12px;
    }
  }
</style>
</head>
<body>
<header>
  <h1>PHP MALWARE SCANNER</h1>
</header>

<div class="breadcrumb" aria-label="Folder navigation"></div>

<main>
  <button id="btnScan" aria-label="Scan Selected Directory">Scan Directory</button>

  <table id="resultTable" style="display:none;" aria-live="polite" aria-relevant="all">
    <thead>
      <tr>
        <th>File Detected</th>
        <th>Keyword Detected</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>
</main>

<div id="popup" role="dialog" aria-modal="true" aria-labelledby="popupFilename">
  <button class="close-btn" title="Close">&times;</button>
  <h2 id="popupFilename"></h2>
  <pre id="popupContent"></pre>
</div>

<div id="footer">
  Created by <strong>binyourbae</strong> - #CianjurHacktivist
</div>

<script>
(() => {
  let scanDir = "<?php echo addslashes($defaultDir); ?>";

  const breadcrumb = document.querySelector('.breadcrumb');
  const btnScan = document.getElementById('btnScan');
  const table = document.getElementById('resultTable');
  const tbody = table.querySelector('tbody');
  const popup = document.getElementById('popup');
  const popupContent = document.getElementById('popupContent');
  const popupFilename = document.getElementById('popupFilename');
  const closeBtn = popup.querySelector('.close-btn');

  function updateBreadcrumb(path) {
    const parts = path.split(/[\/\\]+/).filter(p => p !== '');
    let accum = path.startsWith('/') ? '/' : '';
    let html = '';
    parts.forEach(p => {
      accum += (accum.endsWith('/') ? '' : '/') + p;
      html += `<button class="folder-btn" data-path="${accum}">${p}</button> / `;
    });
    if(path === '/' || path === '') html = '<button class="folder-btn" data-path="/">/</button> / ';
    breadcrumb.innerHTML = html.slice(0, -3);
    attachBreadcrumbEvents();
  }

  function attachBreadcrumbEvents() {
    const btns = breadcrumb.querySelectorAll('.folder-btn');
    btns.forEach(btn => {
      btn.onclick = () => {
        scanDir = btn.getAttribute('data-path');
        updateBreadcrumb(scanDir);
        scan();
      };
    });
  }

  async function scan() {
    tbody.innerHTML = '';
    table.style.display = 'none';
    btnScan.disabled = true;
    btnScan.textContent = 'SCANNING...';

    try {
      const res = await fetch(`?action=scan&dir=${encodeURIComponent(scanDir)}`);
      const data = await res.json();
      if (data.error) {
        alert(data.error);
        btnScan.disabled = false;
        btnScan.textContent = 'Scan Directory';
        return;
      }

      if (Object.keys(data).length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" style="color:#a00;">No suspicious files detected.</td></tr>';
      } else {
        for (const [file, keys] of Object.entries(data)) {
          const fileName = file.split(/[\/\\]/).pop();
          const keywords = keys.join(', ');
          const tr = document.createElement('tr');

          tr.innerHTML = `
            <td class="file-name" title="${file}">${fileName}</td>
            <td>${keywords}</td>
            <td class="actions">
              <button class="action-btn view-btn" data-file="${file}">VIEW</button>
              <button class="action-btn rename-btn" data-file="${file}">RENAME</button>
              <button class="action-btn delete-btn" data-file="${file}">DELETE</button>
            </td>
          `;
          tbody.appendChild(tr);
        }
      }

      table.style.display = 'table';

      attachTableEvents();

    } catch (e) {
      alert('Error scanning directory');
    }

    btnScan.disabled = false;
    btnScan.textContent = 'Scan Directory';
  }

  function attachTableEvents() {
    tbody.querySelectorAll('.view-btn').forEach(btn => {
      btn.onclick = async () => {
        const file = btn.getAttribute('data-file');
        popupFilename.textContent = file.split(/[\/\\]/).pop();
        popupContent.textContent = 'Loading...';
        popup.style.display = 'block';
        try {
          const res = await fetch(`?action=viewfile&file=${encodeURIComponent(file)}`);
          const data = await res.json();
          if (data.error) {
            popupContent.textContent = data.error;
          } else {
            popupContent.textContent = data.content;
          }
        } catch {
          popupContent.textContent = 'Failed to load file content';
        }
      };
    });

    tbody.querySelectorAll('.delete-btn').forEach(btn => {
      btn.onclick = async () => {
        if (!confirm('Delete this file? This action cannot be undone.')) return;
        const file = btn.getAttribute('data-file');
        btn.disabled = true;
        try {
          const res = await fetch(`?action=deletefile`, {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: `file=${encodeURIComponent(file)}`
          });
          const data = await res.json();
          alert(data.success || data.error);
          if (data.success) scan();
        } catch {
          alert('Failed to delete file');
        }
        btn.disabled = false;
      };
    });

    tbody.querySelectorAll('.rename-btn').forEach(btn => {
      btn.onclick = () => {
        const file = btn.getAttribute('data-file');
        const oldName = file.split(/[\/\\]/).pop();
        const newname = prompt('Enter new filename:', oldName);
        if (!newname || newname.trim() === '') return;
        btn.disabled = true;
        fetch(`?action=renamefile`, {
          method: 'POST',
          headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body: `file=${encodeURIComponent(file)}&newname=${encodeURIComponent(newname)}`
        }).then(res => res.json()).then(data => {
          alert(data.success || data.error);
          if (data.success) scan();
          btn.disabled = false;
        }).catch(() => {
          alert('Failed to rename file');
          btn.disabled = false;
        });
      };
    });
  }

  closeBtn.onclick = () => {
    popup.style.display = 'none';
    popupContent.textContent = '';
    popupFilename.textContent = '';
  };

  // Init UI
  updateBreadcrumb(scanDir);
  btnScan.onclick = scan;

})();
</script>

</body>
</html>
