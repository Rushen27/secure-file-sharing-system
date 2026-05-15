<?php
session_start();
include "config/database.php";

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    die("Access Denied.");
}



// Get stats
$total_users  = $conn->query("SELECT COUNT(*) as t FROM users")->fetch_assoc()['t'];
$total_files  = $conn->query("SELECT COUNT(*) as t FROM files")->fetch_assoc()['t'];
$total_logs   = $conn->query("SELECT COUNT(*) as t FROM logs")->fetch_assoc()['t'];
$locked_users = $conn->query("SELECT COUNT(*) as t FROM users WHERE locked_until > NOW()")->fetch_assoc()['t'];
$today_actions= $conn->query("SELECT COUNT(*) as t FROM logs WHERE DATE(logged_at) = CURDATE()")->fetch_assoc()['t'];
$total_shares = $conn->query("SELECT COUNT(*) as t FROM shares WHERE expires_at > NOW()")->fetch_assoc()['t'];

// Filter
$filter = $_GET['filter'] ?? 'ALL';
$allowed_filters = ['ALL','LOGIN','UPLOAD','DOWNLOAD','SHARE','DELETE','ACCOUNT_LOCKED','TAMPERING_DETECTED'];
if (!in_array($filter, $allowed_filters)) $filter = 'ALL';

// Get logs with filter
if ($filter === 'ALL') {
    $logs_stmt = $conn->prepare("
        SELECT l.*, u.username FROM logs l 
        JOIN users u ON u.id = l.user_id 
        ORDER BY l.logged_at DESC LIMIT 100
    ");
    $logs_stmt->execute();
} else {
    $logs_stmt = $conn->prepare("
        SELECT l.*, u.username FROM logs l 
        JOIN users u ON u.id = l.user_id 
        WHERE l.action = ?
        ORDER BY l.logged_at DESC LIMIT 100
    ");
    $logs_stmt->bind_param("s", $filter);
    $logs_stmt->execute();
}
$logs = $logs_stmt->get_result();

// Get all users
$users = $conn->query("SELECT * FROM users ORDER BY created_at DESC");

// Get all files
$files = $conn->query("SELECT f.*, u.username FROM files f JOIN users u ON u.id = f.user_id ORDER BY f.uploaded_at DESC");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel — SecureShare</title>
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
        .container { max-width: 1100px; margin: 0 auto; }
        .navbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
        }
        .navbar .logo { font-family: var(--mono); font-size: 1rem; font-weight: 600; color: var(--danger); }
        .navbar-right { display: flex; align-items: center; gap: 1.5rem; }
        .live-badge {
            display: flex; align-items: center; gap: 6px;
            font-family: var(--mono); font-size: 0.7rem; color: var(--accent);
        }
        .live-dot {
            width: 7px; height: 7px; border-radius: 50%;
            background: var(--accent);
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50%       { opacity: 0.4; transform: scale(0.8); }
        }
        .navbar a { font-family: var(--mono); font-size: 0.75rem; color: var(--muted); text-decoration: none; }
        .navbar a:hover { color: var(--text); }

        /* Stats */
        .stats {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 0.75rem;
            margin-bottom: 2rem;
        }
        @media(max-width:800px) { .stats { grid-template-columns: repeat(3,1fr); } }
        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 1rem;
            position: relative;
            overflow: hidden;
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
        }
        .stat-card.c-green::before  { background: var(--accent); }
        .stat-card.c-blue::before   { background: var(--accent2); }
        .stat-card.c-red::before    { background: var(--danger); }
        .stat-card.c-orange::before { background: var(--warning); }
        .stat-num {
            font-family: var(--mono);
            font-size: 1.8rem;
            font-weight: 600;
            margin-bottom: 0.2rem;
        }
        .stat-card.c-green .stat-num  { color: var(--accent); }
        .stat-card.c-blue .stat-num   { color: var(--accent2); }
        .stat-card.c-red .stat-num    { color: var(--danger); }
        .stat-card.c-orange .stat-num { color: var(--warning); }
        .stat-label { font-family: var(--mono); font-size: 0.62rem; color: var(--muted); letter-spacing: 0.06em; }

        /* Section */
        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 0.75rem;
            margin-top: 2rem;
        }
        .section-title { font-family: var(--mono); font-size: 0.75rem; color: var(--muted); letter-spacing: 0.08em; }

        /* Filter tabs */
        .filter-tabs { display: flex; gap: 0.4rem; flex-wrap: wrap; }
        .filter-tab {
            font-family: var(--mono);
            font-size: 0.65rem;
            padding: 3px 10px;
            border-radius: 20px;
            border: 1px solid var(--border);
            color: var(--muted);
            text-decoration: none;
            transition: all 0.2s;
        }
        .filter-tab:hover { border-color: var(--accent2); color: var(--text); }
        .filter-tab.active { background: var(--accent2); border-color: var(--accent2); color: #fff; }
        .filter-tab.f-upload.active    { background: var(--accent);  border-color: var(--accent);  color: #000; }
        .filter-tab.f-download.active  { background: var(--accent2); border-color: var(--accent2); color: #fff; }
        .filter-tab.f-share.active     { background: var(--warning); border-color: var(--warning); color: #000; }
        .filter-tab.f-locked.active,
        .filter-tab.f-tamper.active    { background: var(--danger);  border-color: var(--danger);  color: #fff; }
        .filter-tab.f-login.active     { background: var(--muted);   border-color: var(--muted);   color: #fff; }

        /* Auto refresh indicator */
        .refresh-bar {
            height: 2px;
            background: var(--border);
            border-radius: 2px;
            margin-bottom: 0.75rem;
            overflow: hidden;
        }
        .refresh-progress {
            height: 100%;
            background: var(--accent);
            border-radius: 2px;
            animation: refill 30s linear infinite;
        }
        @keyframes refill {
            from { width: 100%; }
            to   { width: 0%; }
        }

        /* Table */
        .table-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 1rem;
        }
        table { width: 100%; border-collapse: collapse; }
        thead { background: rgba(255,255,255,0.02); border-bottom: 1px solid var(--border); }
        th {
            font-family: var(--mono);
            font-size: 0.65rem;
            color: var(--muted);
            letter-spacing: 0.08em;
            padding: 0.75rem 1rem;
            text-align: left;
        }
        td {
            font-size: 0.78rem;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid rgba(255,255,255,0.03);
            color: var(--text);
            font-family: var(--mono);
        }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255,255,255,0.02); }

        /* Action badges */
        .action-badge {
            display: inline-block;
            font-size: 0.65rem;
            padding: 2px 8px;
            border-radius: 20px;
            font-weight: 600;
        }
        .ab-LOGIN    { background: rgba(90,96,112,0.2);  color: var(--muted);   border: 1px solid rgba(90,96,112,0.3); }
        .ab-UPLOAD   { background: rgba(0,229,160,0.1);  color: var(--accent);  border: 1px solid rgba(0,229,160,0.3); }
        .ab-DOWNLOAD { background: rgba(0,119,255,0.1);  color: var(--accent2); border: 1px solid rgba(0,119,255,0.3); }
        .ab-SHARE    { background: rgba(255,165,2,0.1);  color: var(--warning); border: 1px solid rgba(255,165,2,0.3); }
        .ab-DELETE   { background: rgba(255,71,87,0.1);  color: var(--danger);  border: 1px solid rgba(255,71,87,0.3); }
        .ab-ACCOUNT_LOCKED       { background: rgba(255,71,87,0.15); color: var(--danger);  border: 1px solid rgba(255,71,87,0.4); }
        .ab-TAMPERING_DETECTED   { background: rgba(255,71,87,0.25); color: #ff0000;        border: 1px solid rgba(255,0,0,0.5); }

        .badge-admin { font-size: 0.65rem; background: rgba(255,71,87,0.15); color: var(--danger); border: 1px solid rgba(255,71,87,0.3); padding: 2px 8px; border-radius: 20px; }
        .badge-user  { font-size: 0.65rem; background: rgba(0,119,255,0.1);  color: var(--accent2); border: 1px solid rgba(0,119,255,0.2); padding: 2px 8px; border-radius: 20px; }
        .badge-locked { font-size: 0.65rem; background: rgba(255,71,87,0.1); color: var(--danger); border: 1px solid rgba(255,71,87,0.2); padding: 2px 8px; border-radius: 20px; }

        .time-ago { color: var(--muted); font-size: 0.7rem; }
        .empty-state { text-align: center; padding: 2rem; color: var(--muted); font-family: var(--mono); font-size: 0.8rem; }
    </style>
</head>
<body>
<div class="container">

    <div class="navbar">
        <div class="logo">⚠ ADMIN_PANEL</div>
        <div class="navbar-right">
            <div class="live-badge">
                <div class="live-dot"></div>
                LIVE — auto refresh 30s
            </div>
            <a href="dashboard.php">← Dashboard</a>
        </div>
    </div>

    <!-- Stats -->
    <div class="stats">
        <div class="stat-card c-green">
            <div class="stat-num"><?= $total_users ?></div>
            <div class="stat-label">TOTAL USERS</div>
        </div>
        <div class="stat-card c-blue">
            <div class="stat-num"><?= $total_files ?></div>
            <div class="stat-label">TOTAL FILES</div>
        </div>
        <div class="stat-card c-green">
            <div class="stat-num"><?= $total_shares ?></div>
            <div class="stat-label">ACTIVE SHARES</div>
        </div>
        <div class="stat-card c-blue">
            <div class="stat-num"><?= $total_logs ?></div>
            <div class="stat-label">TOTAL ACTIONS</div>
        </div>
        <div class="stat-card c-orange">
            <div class="stat-num"><?= $today_actions ?></div>
            <div class="stat-label">TODAY'S ACTIONS</div>
        </div>
        <div class="stat-card c-red">
            <div class="stat-num"><?= $locked_users ?></div>
            <div class="stat-label">LOCKED ACCOUNTS</div>
        </div>
    </div>

    <!-- Live Audit Log -->
    <div class="section-header">
        <div class="section-title">🔴 LIVE AUDIT LOG</div>
        <div class="filter-tabs">
            <a href="?filter=ALL"               class="filter-tab <?= $filter==='ALL'?'active':'' ?>">ALL</a>
            <a href="?filter=LOGIN"             class="filter-tab f-login    <?= $filter==='LOGIN'?'active':'' ?>">LOGIN</a>
            <a href="?filter=UPLOAD"            class="filter-tab f-upload   <?= $filter==='UPLOAD'?'active':'' ?>">UPLOAD</a>
            <a href="?filter=DOWNLOAD"          class="filter-tab f-download <?= $filter==='DOWNLOAD'?'active':'' ?>">DOWNLOAD</a>
            <a href="?filter=SHARE"             class="filter-tab f-share    <?= $filter==='SHARE'?'active':'' ?>">SHARE</a>
            <a href="?filter=DELETE"            class="filter-tab f-locked   <?= $filter==='DELETE'?'active':'' ?>">DELETE</a>
            <a href="?filter=ACCOUNT_LOCKED"    class="filter-tab f-locked   <?= $filter==='ACCOUNT_LOCKED'?'active':'' ?>">LOCKED</a>
            <a href="?filter=TAMPERING_DETECTED" class="filter-tab f-tamper  <?= $filter==='TAMPERING_DETECTED'?'active':'' ?>">⚠ TAMPER</a>
        </div>
    </div>

    <!-- Auto refresh progress bar -->
    <div class="refresh-bar"><div class="refresh-progress"></div></div>

    <div class="table-card">
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>USER</th>
                    <th>ACTION</th>
                    <th>FILE</th>
                    <th>IP ADDRESS</th>
                    <th>TIME</th>
                </tr>
            </thead>
            <tbody id="logBody">
                <?php
                $rows = $logs->fetch_all(MYSQLI_ASSOC);
                if (empty($rows)):
                ?>
                <tr><td colspan="6" class="empty-state">No logs found for this filter.</td></tr>
                <?php else: ?>
                <?php foreach ($rows as $i => $l): ?>
                <tr>
                    <td class="time-ago"><?= $i + 1 ?></td>
                    <td>👤 <?= htmlspecialchars($l['username']) ?></td>
                    <td>
                        <span class="action-badge ab-<?= htmlspecialchars($l['action']) ?>">
                            <?= htmlspecialchars($l['action']) ?>
                        </span>
                    </td>
                    <td><?= htmlspecialchars($l['file_name'] ?? '—') ?></td>
                    <td class="time-ago"><?= htmlspecialchars($l['ip_address'] ?? '—') ?></td>
                    <td class="time-ago" title="<?= $l['logged_at'] ?>">
                        <?= date('d M Y, H:i:s', strtotime($l['logged_at'])) ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Users Table -->
    <div class="section-header">
        <div class="section-title">ALL USERS</div>
    </div>
    <div class="table-card">
        <table>
            <thead>
                <tr><th>ID</th><th>USERNAME</th><th>ROLE</th><th>STATUS</th><th>JOINED</th></tr>
            </thead>
            <tbody>
                <?php while ($u = $users->fetch_assoc()):
                    $is_locked = $u['locked_until'] && strtotime($u['locked_until']) > time();
                ?>
                <tr>
                    <td><?= $u['id'] ?></td>
                    <td>👤 <?= htmlspecialchars($u['username']) ?></td>
                    <td><span class="badge-<?= $u['role'] ?>"><?= strtoupper($u['role']) ?></span></td>
                    <td>
                        <?php if ($is_locked): ?>
                            <span class="badge-locked">🔒 LOCKED</span>
                        <?php else: ?>
                            <span style="color:var(--accent);font-size:0.7rem;">● ACTIVE</span>
                        <?php endif; ?>
                    </td>
                    <td class="time-ago"><?= date('d M Y', strtotime($u['created_at'])) ?></td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>

    <!-- Files Table -->
    <div class="section-header">
        <div class="section-title">ALL FILES</div>
    </div>
    <div class="table-card">
        <table>
            <thead>
                <tr><th>FILE NAME</th><th>OWNER</th><th>HASH (SHA-256)</th><th>UPLOADED</th></tr>
            </thead>
            <tbody>
                <?php while ($f = $files->fetch_assoc()): ?>
                <tr>
                    <td>📄 <?= htmlspecialchars($f['file_name']) ?></td>
                    <td>👤 <?= htmlspecialchars($f['username']) ?></td>
                    <td class="time-ago" style="font-size:0.65rem;"><?= substr($f['file_hash'], 0, 20) ?>...</td>
                    <td class="time-ago"><?= date('d M Y, H:i', strtotime($f['uploaded_at'])) ?></td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>

</div>

<script>
    // Auto refresh every 30 seconds
    setTimeout(() => location.reload(), 30000);
</script>
</body>
</html>