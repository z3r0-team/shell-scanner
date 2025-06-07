<?php
set_time_limit(0);
$defaultDir = str_replace('\\', '/', getcwd());

function formatSizeUnits($bytes) {
    if ($bytes >= 1048576) return number_format($bytes / 1048576, 2) . ' MB';
    if ($bytes >= 1024) return number_format($bytes / 1024, 2) . ' KB';
    if ($bytes > 0) return $bytes . ' B';
    return '0 B';
}

function getPerms($path) {
    return substr(sprintf('%o', @fileperms($path)), -4);
}

function scanFileSystem($dir, &$results) {
    $items = @scandir($dir);
    if ($items === false) return;

    $keywords = ['base64_decode', 'Webshell', 'Priv8', '<?=', '/^data:.*;base64,/'];
    $obfuscationPatterns = [
        'eval' => '/\b(eval|assert|create_function)\s*\(/i',
        'gzuncompress' => '/(gzuncompress|gzinflate|str_rot13)\s*\(\s*base64_decode\s*\(/i',
        'long_hex' => '/[a-f0-9]{200,}/i',
        'hex_string' => '/(\\x[a-f0-9]{2,}){20,}/i'
    ];
    $extPattern = '/\.(php|phtml|php5|php7|shtml|inc|phar)$/i';

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $fullPath = $dir . DIRECTORY_SEPARATOR . $item;
        $normalizedPath = str_replace('\\', '/', $fullPath);
        $isDir = is_dir($fullPath);

        if ($isDir) {
            scanFileSystem($fullPath, $results);
        } elseif (preg_match($extPattern, $item)) {
            $content = @file_get_contents($fullPath);
            if ($content === false) continue;
            
            $detections = [];
            foreach ($keywords as $key) {
                if (preg_match($key, $content)) {
                    $detections[] = trim($key, '/i');
                }
            }
            foreach ($obfuscationPatterns as $name => $pattern) {
                if (preg_match($pattern, $content)) {
                    $detections[] = "OBFUSCATED: " . $name;
                }
            }

            if (!empty($detections)) {
                $fileInfo = [
                    'path' => $normalizedPath,
                    'name' => $item,
                    'type' => 'File',
                    'size' => formatSizeUnits(@filesize($fullPath)),
                    'perms' => getPerms($fullPath),
                    'writable' => is_writable($fullPath),
                    'detections' => array_unique($detections)
                ];
                $results[] = $fileInfo;
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action'])) {
    $action = $_GET['action'];
    $dir = isset($_GET['dir']) ? str_replace('\\', '/', $_GET['dir']) : $defaultDir;

    if ($action === 'scan_dir') {
        if (!is_dir($dir) || !is_readable($dir)) {
            echo json_encode(['error' => 'Directory not found or not readable.']);
            exit;
        }
        $results = [];
        scanFileSystem($dir, $results);
        usort($results, function($a, $b) {
            return strcasecmp($a['path'], $b['path']);
        });
        echo json_encode($results);
        exit;
    }

    if ($action === 'view_file') {
        $file = $_GET['file'] ?? '';
        if (!is_file($file)) {
            echo json_encode(['error' => 'File not found.']);
            exit;
        }
        if (!is_readable($file)) {
             echo json_encode(['error' => 'File is not readable. Permissions: ' . getPerms($file)]);
             exit;
        }
        echo json_encode(['content' => file_get_contents($file)]);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    $action = $data['action'] ?? '';
    
    if ($action === 'delete_path') {
        $path = $data['path'] ?? '';
        if (!file_exists($path) || is_dir($path)) {
            echo json_encode(['error' => 'Path not found or is a directory.']);
            exit;
        }
        @chmod($path, 0777);
        if (@unlink($path)) {
            echo json_encode(['success' => 'File deleted.']);
        } else {
            echo json_encode(['error' => 'Failed to delete file.']);
        }
        exit;
    }

    if ($action === 'delete_multiple') {
        $paths = $data['paths'] ?? [];
        $deletedCount = 0;
        $errors = [];
        foreach($paths as $path) {
            if (file_exists($path) && !is_dir($path)) {
                @chmod($path, 0777);
                if (@unlink($path)) {
                    $deletedCount++;
                } else {
                    $errors[] = $path;
                }
            } else {
                 $errors[] = $path . ' (not found)';
            }
        }
        $message = "Successfully deleted $deletedCount files.";
        if (!empty($errors)) {
            $message .= " Failed to delete: " . implode(', ', $errors);
        }
        echo json_encode(['success' => $message]);
        exit;
    }

    if ($action === 'save_file') {
        $path = $data['path'] ?? '';
        $content = $data['content'] ?? '';
        if (!is_file($path) || !is_writable($path)) {
            echo json_encode(['error' => 'File not found or not writable.']);
            exit;
        }
        if (file_put_contents($path, $content) !== false) {
            echo json_encode(['success' => 'File saved successfully.']);
        } else {
            echo json_encode(['error' => 'Failed to save file.']);
        }
        exit;
    }
}

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>PHP Malware Scanner</title>
<link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap" rel="stylesheet" />
<style>
:root { --main-color: #00ff00; --bg-color: #04190f; --header-bg: #002b08; --border-color: #00440f; --red-color: #ff4d4d; --yellow-color: #ffd700; --blue-color: #00aaff; --grey-color: #888; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg-color); color: var(--main-color); font-family: 'Press Start 2P', cursive, monospace; font-size: 12px; line-height: 1.5; }
header { background: var(--header-bg); padding: 1rem; border-bottom: 2px solid var(--main-color); text-align: center; }
header h1 { margin: 0; font-size: 1.4rem; text-shadow: 0 0 5px var(--main-color), 0 0 10px var(--main-color); }
.breadcrumb { background: #003214; padding: 0.5rem 1rem; border-bottom: 2px solid var(--main-color); display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
.breadcrumb-part { background: transparent; border: 1px solid var(--main-color); color: var(--main-color); padding: 6px 10px; cursor: pointer; font-size: 10px; }
.breadcrumb-part:hover { background: var(--main-color); color: var(--bg-color); }
main { padding: 1rem; }
.toolbar { margin-bottom: 1rem; }
.toolbar button { background: var(--red-color); border: 1px solid var(--main-color); color: var(--bg-color); cursor: pointer; font-size: 10px; padding: 8px 12px; font-family: 'Press Start 2P'; }
.toolbar button:hover { background: var(--main-color); color: var(--bg-color); }
table { width: 100%; border-collapse: collapse; table-layout: fixed; }
thead th { padding: 10px 8px; text-align: left; background: var(--header-bg); }
thead th:first-child { width: 40px; }
thead th:nth-child(2) { width: 40%; }
tbody tr:nth-child(odd) { background: #012e0b; } tbody tr:nth-child(even) { background: #021f07; }
tbody tr:hover { background: #003214; }
tbody td { padding: 8px 10px; vertical-align: middle; word-wrap: break-word; }
.path-name { cursor: pointer; }
.path-name:hover { text-decoration: underline; }
.status-tag { display: inline-block; font-size: 9px; padding: 3px 6px; margin: 2px; border-radius: 4px; color: black; }
.tag-writable { background-color: var(--main-color); }
.tag-non-writable { background-color: var(--grey-color); color: white; }
.detection-tag { background-color: var(--yellow-color); }
.actions button { background: transparent; border: 1px solid var(--main-color); color: var(--main-color); cursor: pointer; font-size: 10px; padding: 4px 8px; margin-top: 5px; }
.actions button:hover { background: var(--main-color); color: var(--bg-color); }
#popup { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); }
.popup-content { background: var(--bg-color); border: 2px solid var(--main-color); width: 80%; max-width: 900px; height: 80vh; margin: 5% auto; display: flex; flex-direction: column; }
.popup-header { padding: 0.5rem 1rem; border-bottom: 1px solid var(--main-color); display: flex; justify-content: space-between; align-items: center; }
.popup-body { flex-grow: 1; padding: 1rem; overflow: auto; }
#editor { width: 100%; height: 100%; background: #012e0b; border: 1px solid var(--border-color); color: var(--main-color); font-family: 'Courier New', monospace; font-size: 14px; }
.popup-footer { padding: 0.5rem 1rem; border-top: 1px solid var(--main-color); text-align: right; }
</style>
</head>
<body>
<header><h1>z3r0-team!</h1></header>
<div class="breadcrumb"></div>
<main>
    <div class="toolbar">
        <button id="delete-selected">Hapus yang Dipilih</button>
    </div>
    <table id="file-table">
        <thead>
            <tr>
                <th><input type="checkbox" id="select-all"></th>
                <th>File Path</th>
                <th>Detected</th>
                <th>Size</th>
                <th>Permissions</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
</main>
<div id="popup">
    <div class="popup-content">
        <div class="popup-header"><h3 id="popup-title"></h3><button id="popup-close">&times;</button></div>
        <div class="popup-body"><textarea id="editor"></textarea></div>
        <div class="popup-footer"><button id="popup-save">Save</button></div>
    </div>
</div>

<script>
const G = {
    currentDir: "<?php echo addslashes($defaultDir); ?>",
    tbody: document.querySelector('#file-table tbody'),
    breadcrumb: document.querySelector('.breadcrumb'),
    popup: document.getElementById('popup'),
    popupTitle: document.getElementById('popup-title'),
    editor: document.getElementById('editor'),
    popupSave: document.getElementById('popup-save'),
    popupClose: document.getElementById('popup-close'),
    selectAllCheckbox: document.getElementById('select-all'),
    deleteSelectedBtn: document.getElementById('delete-selected'),
};

const renderBreadcrumb = (path) => {
    G.breadcrumb.innerHTML = '';
    if (path.length > 1 && path.endsWith('/')) {
        path = path.slice(0, -1);
    }
    const parts = path.split('/').filter(p => p);
    let cumulativePath = '';

    const rootPart = document.createElement('button');
    rootPart.className = 'breadcrumb-part';
    rootPart.textContent = 'ROOT';
    rootPart.onclick = () => loadDirectory('/');
    G.breadcrumb.appendChild(rootPart);

    parts.forEach((part, index) => {
        if (index === 0 && /^[a-zA-Z]:$/.test(part)) {
            cumulativePath = part + '/';
        } else {
            cumulativePath += (cumulativePath.endsWith('/') ? '' : '/') + part;
        }
        
        const partEl = document.createElement('button');
        partEl.className = 'breadcrumb-part';
        partEl.textContent = part.replace(/:$/, '');
        const pathToLoad = cumulativePath;
        partEl.onclick = () => loadDirectory(pathToLoad);
        G.breadcrumb.appendChild(document.createTextNode(' / '));
        G.breadcrumb.appendChild(partEl);
    });
};

const renderTable = (items) => {
    G.tbody.innerHTML = '<tr><td colspan="7">Loading...</td></tr>';
    if (!items || items.length === 0) {
        G.tbody.innerHTML = '<tr><td colspan="7">Tidak ada file yang terdeteksi cocok dengan keyword.</td></tr>';
        return;
    }
    G.tbody.innerHTML = '';
    items.forEach(item => {
        const tr = document.createElement('tr');
        tr.dataset.path = item.path;
        
        const statusTags = item.writable 
            ? `<span class="status-tag tag-writable">Writable</span>` 
            : `<span class="status-tag tag-non-writable">Non-Writable</span>`;
        
        const detectionTags = item.detections.map(tag => 
            `<span class="status-tag detection-tag">${tag}</span>`
        ).join('');
        
        tr.innerHTML = `
            <td><input type="checkbox" class="file-checkbox"></td>
            <td class="path-name" title="Click to copy path">${item.path}</td>
            <td>${detectionTags}</td>
            <td>${item.size}</td>
            <td>${item.perms}</td>
            <td>${statusTags}</td>
            <td class="actions">
                <button class="action-view">View</button>
                ${item.writable ? '<button class="action-edit">Edit</button>' : ''}
                <button class="action-delete">Delete</button>
            </td>
        `;
        G.tbody.appendChild(tr);
    });
    attachEventListeners();
};

const loadDirectory = async (path) => {
    G.currentDir = path;
    renderBreadcrumb(path);
    G.tbody.innerHTML = '<tr><td colspan="7">Scanning...</td></tr>';
    try {
        const response = await fetch(`?action=scan_dir&dir=${encodeURIComponent(path)}`);
        const data = await response.json();
        if (data.error) {
            alert(data.error);
            G.tbody.innerHTML = `<tr><td colspan="7">${data.error}</td></tr>`;
        } else {
            renderTable(data);
        }
    } catch (e) {
        alert('Failed to load directory data.');
        G.tbody.innerHTML = '<tr><td colspan="7">Failed to load directory data.</td></tr>';
    }
};

const attachEventListeners = () => {
    G.tbody.querySelectorAll('.path-name').forEach(el => {
        el.onclick = () => {
            navigator.clipboard.writeText(el.closest('tr').dataset.path).then(() => alert('Full path copied!'));
        };
    });

    G.tbody.querySelectorAll('.action-view, .action-edit').forEach(btn => {
        btn.onclick = async (e) => {
            const tr = e.target.closest('tr');
            const path = tr.dataset.path;
            const isEdit = e.target.classList.contains('action-edit');
            
            G.popupTitle.textContent = path.split(/[\\\/]/).pop();
            G.editor.value = 'Loading content...';
            G.editor.readOnly = !isEdit;
            G.popupSave.style.display = isEdit ? 'inline-block' : 'none';
            G.popup.style.display = 'block';

            const response = await fetch(`?action=view_file&file=${encodeURIComponent(path)}`);
            const data = await response.json();
            G.editor.value = data.content || data.error;
            G.popupSave.dataset.path = path;
        };
    });

    G.tbody.querySelectorAll('.action-delete').forEach(btn => {
        btn.onclick = async (e) => {
            const tr = e.target.closest('tr');
            const path = tr.dataset.path;
            if (!confirm(`Are you sure you want to delete this file?\n${path}`)) return;

            const response = await fetch(window.location.pathname, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'delete_path', path: path })
            });
            const data = await response.json();
            if (data.success) {
                tr.remove();
            }
            alert(data.success || data.error);
        };
    });
};

const init = () => {
    G.popupClose.onclick = () => G.popup.style.display = 'none';
    
    G.popupSave.onclick = async (e) => {
        const path = e.target.dataset.path;
        const content = G.editor.value;
        const response = await fetch(window.location.pathname, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'save_file', path: path, content: content })
        });
        const data = await response.json();
        if(data.success) {
            G.popup.style.display = 'none';
        }
        alert(data.success || data.error);
    };
    
    G.selectAllCheckbox.onchange = (e) => {
        G.tbody.querySelectorAll('.file-checkbox').forEach(checkbox => {
            checkbox.checked = e.target.checked;
        });
    };
    
    G.deleteSelectedBtn.onclick = async () => {
        const selectedCheckboxes = G.tbody.querySelectorAll('.file-checkbox:checked');
        if (selectedCheckboxes.length === 0) {
            alert('No files selected.');
            return;
        }
        
        const pathsToDelete = Array.from(selectedCheckboxes).map(cb => cb.closest('tr').dataset.path);
        
        if (!confirm(`Are you sure you want to delete ${pathsToDelete.length} selected files?`)) return;

        const response = await fetch(window.location.pathname, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'delete_multiple', paths: pathsToDelete })
        });
        const data = await response.json();
        alert(data.success || data.error);
        loadDirectory(G.currentDir);
    };

    loadDirectory(G.currentDir);
};

init();
</script>
</body>
</html>
