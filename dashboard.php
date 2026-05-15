<?php
session_start();
include "config/database.php";

// Protect this page — must be logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id  = $_SESSION['user_id'];
$username = $_SESSION['username'];
$role     = $_SESSION['role'];

// Get user's files
$stmt = $conn->prepare("SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$files = $stmt->get_result();
$stmt->close();

// Get files shared with this user (not expired)
$shared_with_me = $conn->prepare("
    SELECT f.*, u.username as owner, s.expires_at
    FROM shares s
    JOIN files f ON f.id = s.file_id
    JOIN users u ON u.id = f.user_id
    WHERE s.shared_with = ?
    AND s.expires_at > NOW()
    ORDER BY s.expires_at ASC
");
$shared_with_me->bind_param("i", $user_id);
$shared_with_me->execute();
$shared_files = $shared_with_me->get_result();
$shared_with_me->close();

// Count total files
$count_stmt = $conn->prepare("SELECT COUNT(*) as total FROM files WHERE user_id = ?");
$count_stmt->bind_param("i", $user_id);
$count_stmt->execute();
$count = $count_stmt->get_result()->fetch_assoc()['total'];
$count_stmt->close();

// Count shared files
$shared_stmt = $conn->prepare("SELECT COUNT(*) as total FROM shares WHERE shared_by = ?");
$shared_stmt->bind_param("i", $user_id);
$shared_stmt->execute();
$shared_count = $shared_stmt->get_result()->fetch_assoc()['total'];
$shared_stmt->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard — SecureShare</title>
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
            --mono:    'IBM Plex Mono', monospace;
            --sans:    'IBM Plex Sans', sans-serif;
        }
        body {
            background: var(--bg);
            color: var(--text);
            font-family: var(--sans);
            min-height: 100vh;
            padding: 2rem;
            background-image:
                radial-gradient(ellipse 60% 50% at 70% 20%, rgba(0,119,255,0.07) 0%, transparent 60%),
                radial-gradient(ellipse 40% 40% at 20% 80%, rgba(0,229,160,0.05) 0%, transparent 60%);
        }
        .container { max-width: 900px; margin: 0 auto; }

        /* Top nav */
        .navbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
        }
        .navbar .logo {
            font-family: var(--mono);
            font-size: 1rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            color: var(--accent);
        }
        .navbar .nav-links { display: flex; gap: 1rem; align-items: center; }
        .navbar .nav-links a {
            font-family: var(--mono);
            font-size: 0.75rem;
            color: var(--muted);
            text-decoration: none;
            transition: color 0.2s;
        }
        .navbar .nav-links a:hover { color: var(--text); }
        .navbar .nav-links a.btn-upload {
            background: linear-gradient(135deg, var(--accent2), var(--accent));
            color: #000;
            padding: 6px 14px;
            border-radius: 4px;
            font-weight: 600;
        }

        /* Welcome */
        .welcome {
            margin-bottom: 1.75rem;
        }
        .welcome h2 {
            font-family: var(--mono);
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        .welcome p {
            font-size: 0.82rem;
            color: var(--muted);
        }
        .welcome span { color: var(--accent); }

        /* Stats */
        .stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 1.25rem;
        }
        .stat-card .stat-num {
            font-family: var(--mono);
            font-size: 2rem;
            font-weight: 600;
            color: var(--accent);
            margin-bottom: 0.25rem;
        }
        .stat-card .stat-label {
            font-family: var(--mono);
            font-size: 0.7rem;
            color: var(--muted);
            letter-spacing: 0.06em;
        }

        /* Files table */
        .section-title {
            font-family: var(--mono);
            font-size: 0.75rem;
            color: var(--muted);
            letter-spacing: 0.08em;
            margin-bottom: 0.75rem;
        }
        .files-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 4px;
            overflow: hidden;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        thead {
            background: rgba(255,255,255,0.02);
            border-bottom: 1px solid var(--border);
        }
        th {
            font-family: var(--mono);
            font-size: 0.68rem;
            color: var(--muted);
            letter-spacing: 0.08em;
            padding: 0.85rem 1.25rem;
            text-align: left;
        }
        td {
            font-size: 0.82rem;
            padding: 0.85rem 1.25rem;
            border-bottom: 1px solid rgba(255,255,255,0.03);
            color: var(--text);
        }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255,255,255,0.02); }

        .file-name {
            font-family: var(--mono);
            font-size: 0.78rem;
            color: var(--text);
        }
        .file-date {
            font-family: var(--mono);
            font-size: 0.72rem;
            color: var(--muted);
        }
        .actions { display: flex; gap: 0.5rem; }
        .btn-action {
            font-family: var(--mono);
            font-size: 0.68rem;
            padding: 4px 10px;
            border-radius: 3px;
            text-decoration: none;
            transition: opacity 0.2s;
        }
        .btn-action:hover { opacity: 0.8; }
        .btn-download { background: rgba(0,119,255,0.15); color: var(--accent2); border: 1px solid rgba(0,119,255,0.3); }
        .btn-share    { background: rgba(0,229,160,0.1);  color: var(--accent);  border: 1px solid rgba(0,229,160,0.2); }
        .btn-delete   { background: rgba(255,71,87,0.1);  color: var(--danger);  border: 1px solid rgba(255,71,87,0.2); }

        .no-files {
            text-align: center;
            padding: 3rem;
            font-family: var(--mono);
            font-size: 0.82rem;
            color: var(--muted);
        }
        .no-files a {
            color: var(--accent);
            text-decoration: none;
        }

        /* Admin badge */
        .admin-badge {
            font-family: var(--mono);
            font-size: 0.65rem;
            background: rgba(255,71,87,0.15);
            color: var(--danger);
            border: 1px solid rgba(255,71,87,0.3);
            padding: 2px 8px;
            border-radius: 20px;
            margin-left: 0.5rem;
        }
    </style>
</head>
<body>
<div class="container">

    <!-- Navbar -->
    <div class="navbar">
        <div class="logo">🔐 SECURE_SHARE</div>
        <div class="nav-links">
            <?php if ($role === 'admin'): ?>
            <a href="admin.php">Admin Panel</a>
            <?php endif; ?>
            <a href="upload.php" class="btn-upload">⬆ Upload</a>
            <a href="logout.php">Logout</a>
        </div>
    </div>

    <!-- Welcome -->
    <div class="welcome">
        <h2>Welcome, <span><?= htmlspecialchars($username) ?></span>
            <?php if ($role === 'admin'): ?>
            <span class="admin-badge">ADMIN</span>
            <?php endif; ?>
        </h2>
        <p>Here are all your encrypted files.</p>
    </div>

    <!-- Stats -->
    <div class="stats">
        <div class="stat-card">
            <div class="stat-num"><?= $count ?></div>
            <div class="stat-label">TOTAL FILES</div>
        </div>
        <div class="stat-card">
            <div class="stat-num"><?= $shared_count ?></div>
            <div class="stat-label">FILES SHARED</div>
        </div>
        <div class="stat-card">
            <div class="stat-num">AES</div>
            <div class="stat-label">ENCRYPTION</div>
        </div>
    </div>

    <!-- Files -->
    <div class="section-title">YOUR FILES</div>
    <div class="files-card">
        <!-- Shared With Me -->
<div class="section-title" style="margin-top:2rem;">SHARED WITH ME</div>
<div class="files-card">
    <?php
    $shared_rows = $shared_files->fetch_all(MYSQLI_ASSOC);
    if (empty($shared_rows)):
    ?>
    <div class="no-files">No files shared with you yet.</div>
    <?php else: ?>
    <table>
        <thead>
            <tr>
                <th>FILE NAME</th>
                <th>SHARED BY</th>
                <th>EXPIRES</th>
                <th>ACTION</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($shared_rows as $sf): ?>
            <tr>
                <td class="file-name">📄 <?= htmlspecialchars($sf['file_name']) ?></td>
                <td class="file-date">👤 <?= htmlspecialchars($sf['owner']) ?></td>
                <td class="file-date">⏳ <?= date('d M Y', strtotime($sf['expires_at'])) ?></td>
                <td>
                    <a href="download.php?id=<?= $sf['id'] ?>" class="btn-action btn-download">⬇ Download</a>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>
</div>
        <?php if ($count == 0): ?>
        <div class="no-files">
            No files yet. <a href="upload.php">Upload your first file →</a>
        </div>
        <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>FILE NAME</th>
                    <th>UPLOADED</th>
                    <th>ACTIONS</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($file = $files->fetch_assoc()): ?>
                <tr>
                    <td class="file-name">📄 <?= htmlspecialchars($file['file_name']) ?></td>
                    <td class="file-date"><?= date('d M Y, H:i', strtotime($file['uploaded_at'])) ?></td>
                    <td>
                        <div class="actions">
                            <a href="download.php?id=<?= $file['id'] ?>" class="btn-action btn-download">⬇ Download</a>
                            <a href="share.php?file_id=<?= $file['id'] ?>" class="btn-action btn-share">🔗 Share</a>
                            <a href="delete.php?id=<?= $file['id'] ?>" class="btn-action btn-delete"
                               onclick="return confirm('Delete this file?')">🗑 Delete</a>
                        </div>
                    </td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>

</div>
</body>
</html>