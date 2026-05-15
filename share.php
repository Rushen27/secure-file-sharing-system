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

$user_id = $_SESSION['user_id'];
$message = '';
$message_type = '';

$file_id = isset($_GET['file_id']) ? (int)$_GET['file_id'] : 0;

if ($file_id <= 0) {
    die("Invalid file.");
}

// Ownership check
$stmt = $conn->prepare("SELECT * FROM files WHERE id = ? AND user_id = ?");
$stmt->bind_param("ii", $file_id, $user_id);
$stmt->execute();
$file = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$file) {
    die("Access denied. You do not own this file.");
}

// Handle share form
if (isset($_POST['share'])) {

    if (empty($_POST['csrf']) || !hash_equals($_SESSION['csrf'], $_POST['csrf'])) {
        die("CSRF validation failed.");
    }
    $_SESSION['csrf'] = bin2hex(random_bytes(32));

    $shared_with = (int)$_POST['user_id'];

    if ($shared_with === $user_id) {
        $message      = "You cannot share a file with yourself.";
        $message_type = "danger";
    } else {

        // Expiry
        $days = isset($_POST['expiry_days']) ? (int)$_POST['expiry_days'] : 7;
        if (!in_array($days, [1, 3, 7, 30])) $days = 7;
        $expires_at = date('Y-m-d H:i:s', strtotime("+{$days} days"));

        // Password protection (optional)
        $raw_password    = trim($_POST['share_password'] ?? '');
        $hashed_password = !empty($raw_password) ? password_hash($raw_password, PASSWORD_BCRYPT) : null;

        // Check if already shared
        $check = $conn->prepare("SELECT id FROM shares WHERE file_id = ? AND shared_with = ?");
        $check->bind_param("ii", $file_id, $shared_with);
        $check->execute();
        $exists = $check->get_result()->fetch_assoc();
        $check->close();

        if ($exists) {
            $upd = $conn->prepare("UPDATE shares SET expires_at = ?, share_password = ? WHERE file_id = ? AND shared_with = ?");
            $upd->bind_param("ssii", $expires_at, $hashed_password, $file_id, $shared_with);
            $upd->execute();
            $upd->close();
            $message      = "Share updated! New expiry: " . date('d M Y', strtotime($expires_at));
            $message_type = "success";
        } else {
            $stmt2 = $conn->prepare("INSERT INTO shares (file_id, shared_with, shared_by, expires_at, share_password) VALUES (?, ?, ?, ?, ?)");
            $stmt2->bind_param("iiiss", $file_id, $shared_with, $user_id, $expires_at, $hashed_password);
            $stmt2->execute();
            $stmt2->close();

           $ip = $_SERVER['REMOTE_ADDR'] ?? '—';
           $log = $conn->prepare("INSERT INTO logs (user_id, action, file_name, ip_address) VALUES (?, 'SHARE', ?, ?)");
           $log->bind_param("iss", $user_id, $file['file_name'], $ip);
            $log->execute();
            $log->close();

            $pw_note      = !empty($raw_password) ? " Password protected 🔐" : "";
            $message      = "File shared successfully! Expires in {$days} day(s).{$pw_note}";
            $message_type = "success";
        }
    }
}

// Get all users except current
$users_stmt = $conn->prepare("SELECT id, username FROM users WHERE id != ? ORDER BY username ASC");
$users_stmt->bind_param("i", $user_id);
$users_stmt->execute();
$users = $users_stmt->get_result();
$users_stmt->close();

// Get existing shares
$shares_stmt = $conn->prepare("
    SELECT u.username, s.expires_at, s.share_password
    FROM shares s
    JOIN users u ON u.id = s.shared_with
    WHERE s.file_id = ? AND s.shared_by = ?
    ORDER BY s.expires_at ASC
");
$shares_stmt->bind_param("ii", $file_id, $user_id);
$shares_stmt->execute();
$existing_shares = $shares_stmt->get_result();
$shares_stmt->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Share File — SecureShare</title>
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
            max-width: 540px;
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
        .card-header h1 {
            font-family: var(--mono);
            font-size: 0.95rem;
            font-weight: 600;
            letter-spacing: 0.04em;
        }
        .file-badge {
            margin-left: auto;
            font-family: var(--mono);
            font-size: 0.68rem;
            color: var(--accent2);
            border: 1px solid rgba(0,119,255,0.3);
            padding: 3px 10px;
            border-radius: 20px;
            max-width: 160px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .card-body { padding: 1.75rem; }
        .alert {
            font-family: var(--mono);
            font-size: 0.8rem;
            padding: 0.85rem 1rem;
            border-radius: 4px;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .alert-success { background: rgba(0,229,160,0.08); border: 1px solid rgba(0,229,160,0.3); color: var(--success); }
        .alert-danger  { background: rgba(255,71,87,0.08);  border: 1px solid rgba(255,71,87,0.3);  color: var(--danger); }
        label {
            display: block;
            font-family: var(--mono);
            font-size: 0.72rem;
            color: var(--muted);
            letter-spacing: 0.06em;
            margin-bottom: 0.5rem;
        }
        select, input[type="password"], input[type="text"] {
            width: 100%;
            padding: 0.75rem 1rem;
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border);
            border-radius: 4px;
            color: var(--text);
            font-family: var(--mono);
            font-size: 0.82rem;
            margin-bottom: 1.25rem;
            transition: border-color 0.2s;
        }
        input[type="password"]:focus,
        input[type="text"]:focus,
        select:focus { outline: none; border-color: var(--accent2); }
        select { appearance: none; cursor: pointer; }
        .pw-toggle {
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
        .pw-toggle input { width: auto; margin: 0; }
        .pw-toggle:hover { color: var(--text); }
        .pw-field { display: none; }
        .pw-field.visible { display: block; }
        .pw-hint {
            font-family: var(--mono);
            font-size: 0.68rem;
            color: var(--muted);
            margin-top: -1rem;
            margin-bottom: 1.25rem;
        }
        .expiry-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 0.5rem;
            margin-bottom: 1.5rem;
        }
        .expiry-option input { display: none; }
        .expiry-option label {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 0.65rem 0.5rem;
            border: 1px solid var(--border);
            border-radius: 4px;
            cursor: pointer;
            transition: border-color 0.2s, background 0.2s;
            font-family: var(--mono);
            font-size: 0.72rem;
            color: var(--muted);
            text-align: center;
            margin: 0;
            letter-spacing: 0;
        }
        .expiry-option label span.num {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 2px;
        }
        .expiry-option input:checked + label {
            border-color: var(--accent);
            background: rgba(0,229,160,0.07);
            color: var(--accent);
        }
        .expiry-option input:checked + label span.num { color: var(--accent); }
        .btn-share {
            width: 100%;
            padding: 0.85rem;
            background: linear-gradient(135deg, var(--accent2), var(--accent));
            border: none;
            border-radius: 4px;
            color: #000;
            font-family: var(--mono);
            font-size: 0.85rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn-share:hover { opacity: 0.9; }
        .section-title {
            font-family: var(--mono);
            font-size: 0.72rem;
            color: var(--muted);
            letter-spacing: 0.08em;
            margin: 1.75rem 0 0.75rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }
        .share-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.65rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            font-size: 0.82rem;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        .share-row:last-child { border-bottom: none; }
        .share-user { font-family: var(--mono); color: var(--text); }
        .share-meta { display: flex; align-items: center; gap: 0.5rem; }
        .expiry-tag {
            font-family: var(--mono);
            font-size: 0.68rem;
            padding: 2px 8px;
            border-radius: 20px;
        }
        .expiry-tag.active  { background: rgba(0,229,160,0.1); color: var(--accent); border: 1px solid rgba(0,229,160,0.2); }
        .expiry-tag.expired { background: rgba(255,71,87,0.1);  color: var(--danger); border: 1px solid rgba(255,71,87,0.2); }
        .pw-tag {
            font-family: var(--mono);
            font-size: 0.68rem;
            padding: 2px 8px;
            border-radius: 20px;
            background: rgba(0,119,255,0.1);
            color: var(--accent2);
            border: 1px solid rgba(0,119,255,0.2);
        }
        .no-shares {
            font-family: var(--mono);
            font-size: 0.78rem;
            color: var(--muted);
            text-align: center;
            padding: 1rem 0;
        }
        .btn-back {
            display: block;
            text-align: center;
            margin-top: 1.25rem;
            font-family: var(--mono);
            font-size: 0.78rem;
            color: var(--muted);
            text-decoration: none;
            transition: color 0.2s;
        }
        .btn-back:hover { color: var(--text); }
    </style>
</head>
<body>
<div class="card">
    <div class="card-header">
        <div class="icon">🔗</div>
        <h1>SHARE_FILE</h1>
        <span class="file-badge" title="<?= htmlspecialchars($file['file_name']) ?>">
            <?= htmlspecialchars($file['file_name']) ?>
        </span>
    </div>
    <div class="card-body">

        <?php if ($message): ?>
        <div class="alert alert-<?= $message_type ?>">
            <?= $message_type === 'success' ? '✓' : '✕' ?>
            <?= htmlspecialchars($message) ?>
        </div>
        <?php endif; ?>

        <form method="POST">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">

            <label>SHARE WITH USER</label>
            <select name="user_id" required>
                <option value="" disabled selected>— Select a user —</option>
                <?php while ($row = $users->fetch_assoc()): ?>
                <option value="<?= (int)$row['id'] ?>">
                    <?= htmlspecialchars($row['username']) ?>
                </option>
                <?php endwhile; ?>
            </select>

            <label>LINK EXPIRY</label>
            <div class="expiry-grid">
                <div class="expiry-option">
                    <input type="radio" name="expiry_days" id="d1" value="1">
                    <label for="d1"><span class="num">1</span>day</label>
                </div>
                <div class="expiry-option">
                    <input type="radio" name="expiry_days" id="d3" value="3">
                    <label for="d3"><span class="num">3</span>days</label>
                </div>
                <div class="expiry-option">
                    <input type="radio" name="expiry_days" id="d7" value="7" checked>
                    <label for="d7"><span class="num">7</span>days</label>
                </div>
                <div class="expiry-option">
                    <input type="radio" name="expiry_days" id="d30" value="30">
                    <label for="d30"><span class="num">30</span>days</label>
                </div>
            </div>

            <!-- Password protection toggle -->
            <label class="pw-toggle">
                <input type="checkbox" id="pwToggle" onchange="togglePw()">
                🔐 Add password protection (optional)
            </label>

            <div class="pw-field" id="pwField">
                <label>SHARE PASSWORD</label>
                <input type="password" name="share_password" id="sharePassword"
                       placeholder="Enter a password for this share"
                       autocomplete="new-password">
                <p class="pw-hint">Recipient must enter this password before downloading.</p>
            </div>

            <button type="submit" name="share" class="btn-share">🔗 SHARE FILE</button>
        </form>

        <!-- Existing shares -->
        <div class="section-title">CURRENTLY SHARED WITH</div>
        <?php
        $share_rows = $existing_shares->fetch_all(MYSQLI_ASSOC);
        if (empty($share_rows)):
        ?>
        <div class="no-shares">Not shared with anyone yet.</div>
        <?php else: ?>
            <?php foreach ($share_rows as $s):
                $expired = strtotime($s['expires_at']) < time();
            ?>
            <div class="share-row">
                <span class="share-user">👤 <?= htmlspecialchars($s['username']) ?></span>
                <span class="share-meta">
                    <?php if (!empty($s['share_password'])): ?>
                    <span class="pw-tag">🔐 password</span>
                    <?php endif; ?>
                    <span class="expiry-tag <?= $expired ? 'expired' : 'active' ?>">
                        <?= $expired ? 'Expired' : 'Until ' . date('d M Y', strtotime($s['expires_at'])) ?>
                    </span>
                </span>
            </div>
            <?php endforeach; ?>
        <?php endif; ?>

        <a href="dashboard.php" class="btn-back">← Back to Dashboard</a>

    </div>
</div>
<script>
function togglePw() {
    const cb    = document.getElementById('pwToggle');
    const field = document.getElementById('pwField');
    const input = document.getElementById('sharePassword');
    field.classList.toggle('visible', cb.checked);
    input.required = cb.checked;
    if (!cb.checked) input.value = '';
}
</script>
</body>
</html>