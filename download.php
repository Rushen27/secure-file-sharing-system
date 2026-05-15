<?php
session_start();
include "config/database.php";

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$file_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

if ($file_id <= 0) {
    die("Invalid file.");
}

// Check ownership OR shared access — also fetch share password
$stmt = $conn->prepare("
    SELECT f.*, s.share_password, (f.user_id = ?) as is_owner
    FROM files f
    LEFT JOIN shares s ON s.file_id = f.id
        AND s.shared_with = ?
        AND s.expires_at > NOW()
    WHERE f.id = ? AND (
        f.user_id = ?
        OR s.id IS NOT NULL
    )
");
$stmt->bind_param("iiii", $user_id, $user_id, $file_id, $user_id);
$stmt->execute();
$file = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$file) {
    die("Access denied or file not found.");
}

// Check if file already destructed
if ($file['destructed']) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>File Destroyed — SecureShare</title>
        <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500&display=swap" rel="stylesheet">
        <style>
            *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
            :root { --bg: #0d0f14; --surface: #141720; --border: #252a38; --danger: #ff4757; --text: #e4e8f0; --muted: #5a6070; --mono: 'IBM Plex Mono', monospace; --sans: 'IBM Plex Sans', sans-serif; }
            body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 2rem; }
            .card { width: 100%; max-width: 420px; background: var(--surface); border: 1px solid rgba(255,71,87,0.3); border-radius: 4px; overflow: hidden; animation: fadeUp 0.4s ease both; }
            @keyframes fadeUp { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
            .card-header { padding: 1.25rem 1.75rem; border-bottom: 1px solid rgba(255,71,87,0.2); display: flex; align-items: center; gap: 0.75rem; background: rgba(255,71,87,0.05); }
            .card-header h1 { font-family: var(--mono); font-size: 0.95rem; font-weight: 600; letter-spacing: 0.04em; color: var(--danger); }
            .card-body { padding: 1.75rem; text-align: center; }
            .boom { font-size: 4rem; margin-bottom: 1rem; animation: shake 0.5s ease; }
            @keyframes shake { 0%,100%{transform:rotate(0)} 25%{transform:rotate(-10deg)} 75%{transform:rotate(10deg)} }
            .msg { font-family: var(--mono); font-size: 0.85rem; color: var(--danger); margin-bottom: 0.5rem; }
            .sub { font-family: var(--mono); font-size: 0.72rem; color: var(--muted); margin-bottom: 1.5rem; }
            .btn-back { display: block; text-align: center; margin-top: 1rem; font-family: var(--mono); font-size: 0.78rem; color: var(--muted); text-decoration: none; padding: 0.75rem; border: 1px solid var(--border); border-radius: 4px; transition: all 0.2s; }
            .btn-back:hover { color: var(--text); border-color: var(--text); }
        </style>
    </head>
    <body>
    <div class="card">
        <div class="card-header">
            <div style="font-size:1.2rem">💣</div>
            <h1>FILE_DESTROYED</h1>
        </div>
        <div class="card-body">
            <div class="boom">💥</div>
            <div class="msg">This file has been permanently destroyed.</div>
            <div class="sub">The owner set this file to self-destruct.<br>It no longer exists on the server.</div>
            <a href="dashboard.php" class="btn-back">← Back to Dashboard</a>
        </div>
    </div>
    </body>
    </html>
    <?php
    exit();
}

// Check time-based self-destruct
if ($file['self_destruct'] && $file['destruct_at'] && strtotime($file['destruct_at']) < time()) {
    // Time expired — destruct now
    $upd = $conn->prepare("UPDATE files SET destructed = 1 WHERE id = ?");
    $upd->bind_param("i", $file['id']);
    $upd->execute();
    $upd->close();

    // Delete physical file
    if (file_exists($file['file_path'])) {
        unlink($file['file_path']);
    }

    // Log
    $log = $conn->prepare("INSERT INTO logs (user_id, action, file_name) VALUES (?, 'FILE_DESTRUCTED', ?)");
    $log->bind_param("is", $user_id, $file['file_name']);
    $log->execute();
    $log->close();

    header("Location: download.php?id={$file_id}");
    exit();
}

// Password check — only for shared users
$needs_password = !$file['is_owner'] && !empty($file['share_password']);
$pw_error       = '';
$pw_verified    = isset($_SESSION['pw_verified_' . $file_id]) && $_SESSION['pw_verified_' . $file_id] === true;

if ($needs_password && !$pw_verified) {
    if (isset($_POST['share_pw'])) {
        if (password_verify($_POST['share_pw'], $file['share_password'])) {
            $_SESSION['pw_verified_' . $file_id] = true;
            $pw_verified = true;
        } else {
            $pw_error = "Incorrect password. Please try again.";
        }
    }

    if (!$pw_verified) {
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Required — SecureShare</title>
            <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500&display=swap" rel="stylesheet">
            <style>
                *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
                :root { --bg: #0d0f14; --surface: #141720; --border: #252a38; --accent: #00e5a0; --accent2: #0077ff; --text: #e4e8f0; --muted: #5a6070; --danger: #ff4757; --mono: 'IBM Plex Mono', monospace; --sans: 'IBM Plex Sans', sans-serif; }
                body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 2rem; background-image: radial-gradient(ellipse 60% 50% at 70% 20%, rgba(0,119,255,0.07) 0%, transparent 60%), radial-gradient(ellipse 40% 40% at 20% 80%, rgba(0,229,160,0.05) 0%, transparent 60%); }
                .card { width: 100%; max-width: 400px; background: var(--surface); border: 1px solid var(--border); border-radius: 4px; overflow: hidden; animation: fadeUp 0.4s ease both; }
                @keyframes fadeUp { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
                .card-header { padding: 1.25rem 1.75rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 0.75rem; }
                .card-header .icon { width: 32px; height: 32px; background: linear-gradient(135deg, var(--accent2), var(--accent)); border-radius: 6px; display: flex; align-items: center; justify-content: center; }
                .card-header h1 { font-family: var(--mono); font-size: 0.95rem; font-weight: 600; letter-spacing: 0.04em; }
                .card-body { padding: 1.75rem; }
                .file-info { background: rgba(0,119,255,0.05); border: 1px solid rgba(0,119,255,0.15); border-radius: 4px; padding: 0.85rem 1rem; margin-bottom: 1.5rem; font-family: var(--mono); font-size: 0.78rem; color: var(--accent2); }
                .alert-danger { font-family: var(--mono); font-size: 0.78rem; padding: 0.85rem 1rem; border-radius: 4px; margin-bottom: 1.25rem; background: rgba(255,71,87,0.08); border: 1px solid rgba(255,71,87,0.3); color: var(--danger); }
                label { display: block; font-family: var(--mono); font-size: 0.7rem; color: var(--muted); letter-spacing: 0.07em; margin-bottom: 0.4rem; }
                input[type="password"] { width: 100%; padding: 0.75rem 1rem; background: rgba(255,255,255,0.03); border: 1px solid var(--border); border-radius: 4px; color: var(--text); font-family: var(--mono); font-size: 0.82rem; transition: border-color 0.2s; margin-bottom: 1.25rem; }
                input[type="password"]:focus { outline: none; border-color: var(--accent2); }
                .btn { width: 100%; padding: 0.85rem; background: linear-gradient(135deg, var(--accent2), var(--accent)); border: none; border-radius: 4px; color: #000; font-family: var(--mono); font-size: 0.85rem; font-weight: 600; letter-spacing: 0.05em; cursor: pointer; transition: opacity 0.2s; }
                .btn:hover { opacity: 0.9; }
                .btn-back { display: block; text-align: center; margin-top: 1rem; font-family: var(--mono); font-size: 0.75rem; color: var(--muted); text-decoration: none; }
                .btn-back:hover { color: var(--text); }
            </style>
        </head>
        <body>
        <div class="card">
            <div class="card-header">
                <div class="icon">🔐</div>
                <h1>PASSWORD_REQUIRED</h1>
            </div>
            <div class="card-body">
                <div class="file-info">📄 <?= htmlspecialchars($file['file_name']) ?></div>
                <?php if ($pw_error): ?>
                <div class="alert-danger">✕ <?= htmlspecialchars($pw_error) ?></div>
                <?php endif; ?>
                <form method="POST">
                    <label>ENTER SHARE PASSWORD</label>
                    <input type="password" name="share_pw" required placeholder="Enter password to access file" autofocus>
                    <button type="submit" class="btn">🔓 UNLOCK & DOWNLOAD</button>
                </form>
                <a href="dashboard.php" class="btn-back">← Back to Dashboard</a>
            </div>
        </div>
        </body>
        </html>
        <?php
        exit();
    }
}

// Read encrypted file
$encrypted_data = file_get_contents($file['file_path']);
if ($encrypted_data === false) {
    die("File not found on server.");
}

// Integrity check
$iv_check        = substr($encrypted_data, 0, 16);
$encrypted_check = substr($encrypted_data, 16);
$decrypted_check = openssl_decrypt($encrypted_check, "AES-256-CBC", ENCRYPT_KEY, OPENSSL_RAW_DATA, $iv_check);
$current_hash    = hash('sha256', $decrypted_check);

if ($current_hash !== $file['file_hash']) {
    $alert = $conn->prepare("INSERT INTO logs (user_id, action, file_name) VALUES (?, 'TAMPERING_DETECTED', ?)");
    $alert->bind_param("is", $user_id, $file['file_name']);
    $alert->execute();
    $alert->close();
    die("⚠️ Security Alert: This file has been tampered with and cannot be downloaded.");
}

// Decrypt
$iv        = substr($encrypted_data, 0, 16);
$encrypted = substr($encrypted_data, 16);
$decrypted = openssl_decrypt($encrypted, "AES-256-CBC", ENCRYPT_KEY, OPENSSL_RAW_DATA, $iv);

if ($decrypted === false) {
    die("Decryption failed.");
}

// ── SELF-DESTRUCT CHECK after successful decrypt ─────────────────
if ($file['self_destruct'] && !$file['destructed']) {

    $new_count = $file['download_count'] + 1;

    // Update download count
    $upd = $conn->prepare("UPDATE files SET download_count = ? WHERE id = ?");
    $upd->bind_param("ii", $new_count, $file['id']);
    $upd->execute();
    $upd->close();

    // Check if should destruct
    $should_destruct = false;
    if ($file['destruct_after_downloads'] && $new_count >= $file['destruct_after_downloads']) {
        $should_destruct = true;
    }

    if ($should_destruct) {
        // Mark as destructed
        $upd2 = $conn->prepare("UPDATE files SET destructed = 1 WHERE id = ?");
        $upd2->bind_param("i", $file['id']);
        $upd2->execute();
        $upd2->close();

        // Delete shares
        $del_shares = $conn->prepare("DELETE FROM shares WHERE file_id = ?");
        $del_shares->bind_param("i", $file['id']);
        $del_shares->execute();
        $del_shares->close();

        // Delete physical file
        if (file_exists($file['file_path'])) {
            unlink($file['file_path']);
        }

        // Log
        $log2 = $conn->prepare("INSERT INTO logs (user_id, action, file_name) VALUES (?, 'FILE_DESTRUCTED', ?)");
        $log2->bind_param("is", $user_id, $file['file_name']);
        $log2->execute();
        $log2->close();
    }
}

// Clear password session
unset($_SESSION['pw_verified_' . $file_id]);

// Log download
$ip  = $_SERVER['REMOTE_ADDR'] ?? '—';
$log = $conn->prepare("INSERT INTO logs (user_id, action, file_name, ip_address) VALUES (?, 'DOWNLOAD', ?, ?)");
$log->bind_param("iss", $user_id, $file['file_name'], $ip);
$log->execute();
$log->close();

// Send file
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($file['file_name']) . '"');
header('Content-Length: ' . strlen($decrypted));
echo $decrypted;
exit();
?>