<?php
session_start();
include "config/database.php";

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

$message = '';
$message_type = '';

function encryptFile($source, $destination, $key) {
    $data      = file_get_contents($source);
    $iv        = random_bytes(16);
    $encrypted = openssl_encrypt($data, "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv);
    file_put_contents($destination, $iv . $encrypted);
}

if (isset($_POST['upload'])) {

    if (empty($_POST['csrf']) || !hash_equals($_SESSION['csrf'], $_POST['csrf'])) {
        die("CSRF validation failed.");
    }
    $_SESSION['csrf'] = bin2hex(random_bytes(32));

    $file      = $_FILES['file']['name'];
    $temp      = $_FILES['file']['tmp_name'];
    $size      = $_FILES['file']['size'];
    $file_hash = hash_file("sha256", $temp);

    if ($size > 5000000) {
        $message      = "File too large. Maximum size is 5MB.";
        $message_type = "danger";
    } else {

        $allowed_extensions = ['pdf', 'docx', 'jpg', 'jpeg', 'png', 'txt'];
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));

        $allowed_mimes = [
            'application/pdf',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'image/jpeg',
            'image/png',
            'text/plain'
        ];
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime  = finfo_file($finfo, $temp);
        finfo_close($finfo);

        if (!in_array($ext, $allowed_extensions) || !in_array($mime, $allowed_mimes)) {
            $message      = "Invalid file type. Allowed: PDF, DOCX, JPG, PNG, TXT.";
            $message_type = "danger";
        } else {

            $new_name = bin2hex(random_bytes(8)) . "_" . time();
            $folder   = "uploads/" . $new_name . ".enc";

            encryptFile($temp, $folder, ENCRYPT_KEY);

            $user_id = $_SESSION['user_id'];

            // Self-destruct settings
            $self_destruct = isset($_POST['self_destruct']) ? 1 : 0;

            $destruct_after_downloads = null;
            $destruct_at = null;

            if ($self_destruct) {
                $destruct_type = $_POST['destruct_type'] ?? 'downloads';

                if ($destruct_type === 'downloads') {
                    $destruct_after_downloads = in_array((int)$_POST['destruct_downloads'], [1, 3, 5, 10])
                        ? (int)$_POST['destruct_downloads'] : 1;
                } elseif ($destruct_type === 'time') {
                    $destruct_days = in_array((int)$_POST['destruct_days'], [1, 3, 7, 14])
                        ? (int)$_POST['destruct_days'] : 1;
                    $destruct_at = date('Y-m-d H:i:s', strtotime("+{$destruct_days} days"));
                } elseif ($destruct_type === 'first') {
                    $destruct_after_downloads = 1;
                }
            }

            // Save to database
            $stmt = $conn->prepare("INSERT INTO files (user_id, file_name, file_path, file_hash, self_destruct, destruct_after_downloads, destruct_at) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("isssiis", $user_id, $file, $folder, $file_hash, $self_destruct, $destruct_after_downloads, $destruct_at);
            $stmt->execute();
            $stmt->close();

            // Log
            $ip  = $_SERVER['REMOTE_ADDR'] ?? '—';
            $log = $conn->prepare("INSERT INTO logs (user_id, action, file_name, ip_address) VALUES (?, 'UPLOAD', ?, ?)");
            $log->bind_param("iss", $user_id, $file, $ip);
            $log->execute();
            $log->close();

            $destruct_note = '';
            if ($self_destruct) {
                if ($destruct_after_downloads) {
                    $destruct_note = " 💣 Self-destructs after {$destruct_after_downloads} download(s).";
                } elseif ($destruct_at) {
                    $destruct_note = " 💣 Self-destructs on " . date('d M Y', strtotime($destruct_at)) . ".";
                }
            }

            $message      = "File encrypted and uploaded successfully!{$destruct_note}";
            $message_type = "success";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload — SecureShare</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        :root {
            --bg:      #0d0f14;
            --surface: #141720;
            --border:  #252a38;
            --accent:  #00e5a0;
            --accent2: #0077ff;
            --text:    #e4e8f0;
            --muted:   #5a6070;
            --danger:  #ff4757;
            --warning: #ffa502;
            --success: #00e5a0;
            --mono:    'IBM Plex Mono', monospace;
            --sans:    'IBM Plex Sans', sans-serif;
        }
        body {
            background: var(--bg);
            color: var(--text);
            font-family: var(--sans);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
            background-image:
                radial-gradient(ellipse 60% 50% at 70% 20%, rgba(0,119,255,0.07) 0%, transparent 60%),
                radial-gradient(ellipse 40% 40% at 20% 80%, rgba(0,229,160,0.05) 0%, transparent 60%);
        }
        .card {
            width: 100%;
            max-width: 520px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 4px;
            overflow: hidden;
            animation: fadeUp 0.4s ease both;
        }
        @keyframes fadeUp {
            from { opacity: 0; transform: translateY(16px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .card-header {
            padding: 1.25rem 1.75rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .card-header .icon {
            width: 32px; height: 32px;
            background: linear-gradient(135deg, var(--accent2), var(--accent));
            border-radius: 6px;
            display: flex; align-items: center; justify-content: center;
        }
        .card-header h1 { font-family: var(--mono); font-size: 0.95rem; font-weight: 600; letter-spacing: 0.04em; }
        .badge { margin-left: auto; font-family: var(--mono); font-size: 0.65rem; color: var(--accent); border: 1px solid rgba(0,229,160,0.3); padding: 2px 8px; border-radius: 20px; }
        .card-body { padding: 1.75rem; }
        .alert { font-family: var(--mono); font-size: 0.8rem; padding: 0.85rem 1rem; border-radius: 4px; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 0.5rem; }
        .alert-success { background: rgba(0,229,160,0.08); border: 1px solid rgba(0,229,160,0.3); color: var(--success); }
        .alert-danger  { background: rgba(255,71,87,0.08);  border: 1px solid rgba(255,71,87,0.3);  color: var(--danger); }
        .drop-zone {
            border: 2px dashed var(--border);
            border-radius: 4px;
            padding: 2.5rem 1.5rem;
            text-align: center;
            cursor: pointer;
            transition: border-color 0.2s, background 0.2s;
            position: relative;
            margin-bottom: 1.25rem;
        }
        .drop-zone:hover, .drop-zone.dragover { border-color: var(--accent); background: rgba(0,229,160,0.04); }
        .drop-zone input[type="file"] { position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; height: 100%; }
        .drop-icon { font-size: 2rem; margin-bottom: 0.75rem; }
        .drop-zone h3 { font-family: var(--mono); font-size: 0.85rem; font-weight: 600; margin-bottom: 0.35rem; }
        .drop-zone p { font-size: 0.75rem; color: var(--muted); }
        .file-chosen { font-family: var(--mono); font-size: 0.78rem; color: var(--accent); margin-top: 0.6rem; }
        .info-row { display: flex; gap: 0.75rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
        .info-pill { font-family: var(--mono); font-size: 0.7rem; color: var(--muted); background: rgba(255,255,255,0.03); border: 1px solid var(--border); border-radius: 3px; padding: 4px 10px; }

        /* Self destruct section */
        .destruct-toggle {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            margin-bottom: 1rem;
            cursor: pointer;
            font-family: var(--mono);
            font-size: 0.78rem;
            color: var(--muted);
            user-select: none;
        }
        .destruct-toggle input { width: auto; margin: 0; cursor: pointer; }
        .destruct-toggle:hover { color: var(--danger); }
        .destruct-panel {
            display: none;
            background: rgba(255,71,87,0.05);
            border: 1px solid rgba(255,71,87,0.2);
            border-radius: 4px;
            padding: 1rem;
            margin-bottom: 1.25rem;
        }
        .destruct-panel.visible { display: block; }
        .destruct-panel label { font-family: var(--mono); font-size: 0.7rem; color: var(--danger); letter-spacing: 0.06em; margin-bottom: 0.5rem; display: block; }
        .destruct-types { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem; margin-bottom: 1rem; }
        .destruct-type input { display: none; }
        .destruct-type label {
            display: flex; flex-direction: column; align-items: center; justify-content: center;
            padding: 0.6rem 0.4rem;
            border: 1px solid rgba(255,71,87,0.2);
            border-radius: 4px;
            cursor: pointer;
            font-family: var(--mono);
            font-size: 0.68rem;
            color: var(--muted);
            text-align: center;
            margin: 0;
            transition: all 0.2s;
        }
        .destruct-type label .icon { font-size: 1.1rem; margin-bottom: 3px; }
        .destruct-type input:checked + label { border-color: var(--danger); background: rgba(255,71,87,0.1); color: var(--danger); }
        .sub-options { display: none; }
        .sub-options.visible { display: block; }
        .option-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.4rem; margin-top: 0.5rem; }
        .option-grid input { display: none; }
        .option-grid label {
            display: flex; align-items: center; justify-content: center;
            padding: 0.5rem;
            border: 1px solid rgba(255,71,87,0.2);
            border-radius: 4px;
            cursor: pointer;
            font-family: var(--mono);
            font-size: 0.72rem;
            color: var(--muted);
            margin: 0;
            transition: all 0.2s;
        }
        .option-grid input:checked + label { border-color: var(--danger); background: rgba(255,71,87,0.1); color: var(--danger); }
        .destruct-warning {
            font-family: var(--mono);
            font-size: 0.68rem;
            color: var(--danger);
            margin-top: 0.75rem;
            opacity: 0.7;
        }

        .btn-upload { width: 100%; padding: 0.85rem; background: linear-gradient(135deg, var(--accent2), var(--accent)); border: none; border-radius: 4px; color: #000; font-family: var(--mono); font-size: 0.85rem; font-weight: 600; letter-spacing: 0.05em; cursor: pointer; transition: opacity 0.2s; }
        .btn-upload:hover { opacity: 0.9; }
        .btn-back { display: block; text-align: center; margin-top: 1rem; font-family: var(--mono); font-size: 0.78rem; color: var(--muted); text-decoration: none; transition: color 0.2s; }
        .btn-back:hover { color: var(--text); }
        .security-note { margin-top: 1.5rem; padding: 0.75rem 1rem; background: rgba(0,119,255,0.05); border-left: 3px solid var(--accent2); border-radius: 0 4px 4px 0; font-size: 0.72rem; color: var(--muted); line-height: 1.6; }
        .security-note strong { color: var(--accent2); }
    </style>
</head>
<body>
<div class="card">
    <div class="card-header">
        <div class="icon">🔐</div>
        <h1>SECURE_UPLOAD</h1>
        <span class="badge">AES-256</span>
    </div>
    <div class="card-body">

        <?php if ($message): ?>
        <div class="alert alert-<?= $message_type ?>">
            <?= $message_type === 'success' ? '✓' : '✕' ?>
            <?= htmlspecialchars($message) ?>
        </div>
        <?php endif; ?>

        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">

            <div class="drop-zone" id="dropZone">
                <input type="file" name="file" id="fileInput" required accept=".pdf,.docx,.jpg,.jpeg,.png,.txt">
                <div class="drop-icon">📁</div>
                <h3>Drop file here or click to browse</h3>
                <p>PDF, DOCX, JPG, PNG, TXT · Max 5MB</p>
                <div class="file-chosen" id="fileChosen"></div>
            </div>

            <div class="info-row">
                <span class="info-pill">🔒 Encrypted at rest</span>
                <span class="info-pill">✓ CSRF protected</span>
                <span class="info-pill">✓ SHA-256 hash</span>
            </div>

            <!-- Self Destruct Toggle -->
            <label class="destruct-toggle">
                <input type="checkbox" id="destructToggle" name="self_destruct" onchange="toggleDestruct()">
                💣 Enable self-destruct (optional)
            </label>

            <div class="destruct-panel" id="destructPanel">
                <label>SELF-DESTRUCT TRIGGER</label>
                <div class="destruct-types">
                    <div class="destruct-type">
                        <input type="radio" name="destruct_type" id="dt_downloads" value="downloads" checked onchange="showSubOptions()">
                        <label for="dt_downloads"><span class="icon">⬇️</span>After N downloads</label>
                    </div>
                    <div class="destruct-type">
                        <input type="radio" name="destruct_type" id="dt_time" value="time" onchange="showSubOptions()">
                        <label for="dt_time"><span class="icon">⏰</span>After N days</label>
                    </div>
                    <div class="destruct-type">
                        <input type="radio" name="destruct_type" id="dt_first" value="first" onchange="showSubOptions()">
                        <label for="dt_first"><span class="icon">👁️</span>First download</label>
                    </div>
                </div>

                <!-- Download count options -->
                <div class="sub-options visible" id="sub_downloads">
                    <label>MAX DOWNLOADS BEFORE DESTROY</label>
                    <div class="option-grid">
                        <input type="radio" name="destruct_downloads" id="dd1" value="1" checked>
                        <label for="dd1">1x</label>
                        <input type="radio" name="destruct_downloads" id="dd3" value="3">
                        <label for="dd3">3x</label>
                        <input type="radio" name="destruct_downloads" id="dd5" value="5">
                        <label for="dd5">5x</label>
                        <input type="radio" name="destruct_downloads" id="dd10" value="10">
                        <label for="dd10">10x</label>
                    </div>
                </div>

                <!-- Time options -->
                <div class="sub-options" id="sub_time">
                    <label>DAYS UNTIL DESTROY</label>
                    <div class="option-grid">
                        <input type="radio" name="destruct_days" id="td1" value="1" checked>
                        <label for="td1">1d</label>
                        <input type="radio" name="destruct_days" id="td3" value="3">
                        <label for="td3">3d</label>
                        <input type="radio" name="destruct_days" id="td7" value="7">
                        <label for="td7">7d</label>
                        <input type="radio" name="destruct_days" id="td14" value="14">
                        <label for="td14">14d</label>
                    </div>
                </div>

                <p class="destruct-warning">⚠ File will be permanently deleted from server. This cannot be undone.</p>
            </div>

            <button type="submit" name="upload" class="btn-upload">
                ⬆ ENCRYPT &amp; UPLOAD
            </button>
        </form>

        <a href="dashboard.php" class="btn-back">← Back to Dashboard</a>

        <div class="security-note">
            <strong>Security:</strong> Files are encrypted with AES-256-CBC before storage.
            Original filenames are never used on disk. All uploads are logged.
        </div>

    </div>
</div>
<script>
    const input    = document.getElementById('fileInput');
    const chosen   = document.getElementById('fileChosen');
    const dropZone = document.getElementById('dropZone');

    input.addEventListener('change', () => {
        if (input.files.length > 0) {
            const name = input.files[0].name;
            const size = (input.files[0].size / 1024).toFixed(1);
            chosen.textContent = `✓ ${name} (${size} KB)`;
        }
    });

    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', e => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            input.files = e.dataTransfer.files;
            const name = input.files[0].name;
            const size = (input.files[0].size / 1024).toFixed(1);
            chosen.textContent = `✓ ${name} (${size} KB)`;
        }
    });

    function toggleDestruct() {
        const cb    = document.getElementById('destructToggle');
        const panel = document.getElementById('destructPanel');
        panel.classList.toggle('visible', cb.checked);
    }

    function showSubOptions() {
        const type = document.querySelector('input[name="destruct_type"]:checked').value;
        document.getElementById('sub_downloads').classList.toggle('visible', type === 'downloads');
        document.getElementById('sub_time').classList.toggle('visible', type === 'time');
    }
</script>
</body>
</html>