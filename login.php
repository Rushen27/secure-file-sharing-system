<?php
session_start();
include "config/database.php";
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit();
}

$message      = '';
$message_type = 'danger';

define('MAX_ATTEMPTS',    5);
define('LOCKOUT_MINUTES', 15);

// ── STEP 2: OTP verify ──────────────────────────────────────────
if (isset($_POST['verify_otp'])) {

    $entered_otp = trim($_POST['otp']);
    $pending_id  = $_SESSION['pending_user_id'] ?? 0;

    if (!$pending_id) {
        header("Location: login.php");
        exit();
    }

    $stmt = $conn->prepare("SELECT id, username, role, otp_code, otp_expires FROM users WHERE id = ?");
    $stmt->bind_param("i", $pending_id);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user || $user['otp_code'] !== $entered_otp) {
        $message      = "Invalid OTP code. Please try again.";
        $message_type = 'danger';
        $show_otp     = true;

    } elseif (strtotime($user['otp_expires']) < time()) {
        $message      = "OTP expired. Please login again.";
        $message_type = 'warning';
        unset($_SESSION['pending_user_id']);
        $show_otp = false;

    } else {
        // Clear OTP
        $clear = $conn->prepare("UPDATE users SET otp_code = NULL, otp_expires = NULL WHERE id = ?");
        $clear->bind_param("i", $user['id']);
        $clear->execute();
        $clear->close();

        // Set session
        $_SESSION['user_id']  = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role']     = $user['role'];
        unset($_SESSION['pending_user_id']);

        // Log
        $ip  = $_SERVER['REMOTE_ADDR'] ?? '—';
        $log = $conn->prepare("INSERT INTO logs (user_id, action, ip_address) VALUES (?, 'LOGIN', ?)");
        $log->bind_param("is", $user['id'], $ip);
        $log->execute();
        $log->close();

        header("Location: dashboard.php");
        exit();
    }

// ── STEP 1: Username + Password ─────────────────────────────────
} elseif (isset($_POST['login'])) {

    $show_otp = false;
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT id, username, password, role, email, failed_attempts, locked_until FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if ($user) {

        if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
            $remaining    = ceil((strtotime($user['locked_until']) - time()) / 60);
            $message      = "Account locked. Try again in {$remaining} minute(s).";
            $message_type = 'warning';

        } elseif (password_verify($password, $user['password'])) {

            // Reset failed attempts
            $reset = $conn->prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?");
            $reset->bind_param("i", $user['id']);
            $reset->execute();
            $reset->close();

            // Generate 6-digit OTP
            $otp        = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
            $otp_expires = date('Y-m-d H:i:s', strtotime('+10 minutes'));

            // Save OTP to DB
            $upd = $conn->prepare("UPDATE users SET otp_code = ?, otp_expires = ? WHERE id = ?");
            $upd->bind_param("ssi", $otp, $otp_expires, $user['id']);
            $upd->execute();
            $upd->close();

            // Send OTP email
            $mail = new PHPMailer(true);
            try {
                $mail->isSMTP();
                $mail->Host       = MAIL_HOST;
                $mail->SMTPAuth   = true;
                $mail->Username   = MAIL_USERNAME;
                $mail->Password   = MAIL_PASSWORD;
                $mail->SMTPSecure = 'tls';
                $mail->Port       = MAIL_PORT;
                $mail->setFrom(MAIL_FROM, 'SecureShare');
                $mail->addAddress($user['email']);
                $mail->isHTML(true);
                $mail->Subject = 'SecureShare — Your OTP Code';
                $mail->Body    = "
                <div style='font-family:monospace;background:#0d0f14;color:#e4e8f0;padding:2rem;border-radius:8px;max-width:400px;margin:auto;'>
                    <h2 style='color:#00e5a0;margin-bottom:1rem;'>🔐 SecureShare 2FA</h2>
                    <p style='color:#5a6070;margin-bottom:1rem;'>Your one-time login code:</p>
                    <div style='font-size:2.5rem;font-weight:bold;letter-spacing:0.5rem;color:#0077ff;background:#141720;padding:1rem;border-radius:4px;text-align:center;margin-bottom:1rem;'>
                        {$otp}
                    </div>
                    <p style='color:#5a6070;font-size:0.8rem;'>This code expires in <strong style='color:#ffa502;'>10 minutes</strong>.</p>
                    <p style='color:#5a6070;font-size:0.8rem;'>If you didn't request this, ignore this email.</p>
                </div>";
                $mail->send();

                $_SESSION['pending_user_id'] = $user['id'];
                $show_otp     = true;
                $message      = "OTP sent to your email! Check inbox.";
                $message_type = 'success';

            } catch (Exception $e) {
                $message      = "Failed to send OTP. Error: " . $mail->ErrorInfo;
                $message_type = 'danger';
            }

        } else {
            $new_attempts = $user['failed_attempts'] + 1;

            if ($new_attempts >= MAX_ATTEMPTS) {
                $locked_until = date('Y-m-d H:i:s', strtotime('+' . LOCKOUT_MINUTES . ' minutes'));
                $upd = $conn->prepare("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?");
                $upd->bind_param("isi", $new_attempts, $locked_until, $user['id']);
                $upd->execute();
                $upd->close();

                $log = $conn->prepare("INSERT INTO logs (user_id, action) VALUES (?, 'ACCOUNT_LOCKED')");
                $log->bind_param("i", $user['id']);
                $log->execute();
                $log->close();

                $message      = "Too many failed attempts. Account locked for " . LOCKOUT_MINUTES . " minutes.";
                $message_type = 'warning';
            } else {
                $remaining_attempts = MAX_ATTEMPTS - $new_attempts;
                $upd = $conn->prepare("UPDATE users SET failed_attempts = ? WHERE id = ?");
                $upd->bind_param("ii", $new_attempts, $user['id']);
                $upd->execute();
                $upd->close();

                $message      = "Invalid password. {$remaining_attempts} attempt(s) remaining.";
                $message_type = 'danger';
            }
        }

    } else {
        $message      = "Invalid username or password.";
        $message_type = 'danger';
    }

} else {
    $show_otp = false;
}

// Attempts bar
$attempts_used = 0;
$is_locked     = false;
if (isset($_POST['username'])) {
    $chk        = $conn->prepare("SELECT failed_attempts, locked_until FROM users WHERE username = ?");
    $user_input = trim($_POST['username']);
    $chk->bind_param("s", $user_input);
    $chk->execute();
    $chk_user = $chk->get_result()->fetch_assoc();
    $chk->close();
    if ($chk_user) {
        $attempts_used = $chk_user['failed_attempts'];
        $is_locked     = $chk_user['locked_until'] && strtotime($chk_user['locked_until']) > time();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login — SecureShare</title>
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
            max-width: 400px;
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
            padding: 1.5rem 1.75rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .card-header .icon {
            width: 34px; height: 34px;
            background: linear-gradient(135deg, var(--accent2), var(--accent));
            border-radius: 6px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.1rem;
        }
        .card-header h1 { font-family: var(--mono); font-size: 0.95rem; font-weight: 600; letter-spacing: 0.04em; }
        .card-body { padding: 1.75rem; }
        .alert { font-family: var(--mono); font-size: 0.78rem; padding: 0.85rem 1rem; border-radius: 4px; margin-bottom: 1.25rem; }
        .alert-danger  { background: rgba(255,71,87,0.08);  border: 1px solid rgba(255,71,87,0.3);  color: var(--danger); }
        .alert-warning { background: rgba(255,165,2,0.08);  border: 1px solid rgba(255,165,2,0.3);  color: var(--warning); }
        .alert-success { background: rgba(0,229,160,0.08);  border: 1px solid rgba(0,229,160,0.3);  color: var(--success); }
        .form-group { margin-bottom: 1.1rem; }
        label { display: block; font-family: var(--mono); font-size: 0.7rem; color: var(--muted); letter-spacing: 0.07em; margin-bottom: 0.4rem; }
        input { width: 100%; padding: 0.75rem 1rem; background: rgba(255,255,255,0.03); border: 1px solid var(--border); border-radius: 4px; color: var(--text); font-family: var(--mono); font-size: 0.82rem; transition: border-color 0.2s; }
        input:focus { outline: none; border-color: var(--accent2); }
        input:disabled { opacity: 0.4; cursor: not-allowed; }
        .btn { width: 100%; padding: 0.85rem; background: linear-gradient(135deg, var(--accent2), var(--accent)); border: none; border-radius: 4px; color: #000; font-family: var(--mono); font-size: 0.85rem; font-weight: 600; letter-spacing: 0.05em; cursor: pointer; margin-top: 0.5rem; transition: opacity 0.2s; }
        .btn:hover { opacity: 0.9; }
        .btn:disabled { opacity: 0.4; cursor: not-allowed; }
        .register-link { display: block; text-align: center; margin-top: 1.25rem; font-family: var(--mono); font-size: 0.75rem; color: var(--muted); }
        .register-link a { color: var(--accent); text-decoration: none; }
        .attempts-bar { display: flex; gap: 4px; margin-top: 0.75rem; }
        .attempts-bar span { flex: 1; height: 3px; border-radius: 2px; background: var(--border); }
        .attempts-bar span.used { background: var(--danger); }
        .otp-hint { font-family: var(--mono); font-size: 0.68rem; color: var(--muted); margin-top: 0.5rem; text-align: center; }
        .otp-input { font-size: 1.5rem; letter-spacing: 0.5rem; text-align: center; font-weight: 600; }
        .back-link { display: block; text-align: center; margin-top: 1rem; font-family: var(--mono); font-size: 0.72rem; color: var(--muted); text-decoration: none; }
        .back-link:hover { color: var(--text); }
    </style>
</head>
<body>
<div class="card">
    <div class="card-header">
        <div class="icon"><?= ($show_otp ?? false) ? '📧' : '🔐' ?></div>
        <h1><?= ($show_otp ?? false) ? 'VERIFY_OTP' : 'SECURE_LOGIN' ?></h1>
    </div>
    <div class="card-body">

        <?php if ($message): ?>
        <div class="alert alert-<?= $message_type ?>">
            <?= $message_type === 'success' ? '✓' : ($message_type === 'warning' ? '🔒' : '✕') ?>
            <?= htmlspecialchars($message) ?>
        </div>
        <?php endif; ?>

        <?php if (isset($_GET['registered'])): ?>
        <div class="alert alert-success">✓ Account created! Please login.</div>
        <?php endif; ?>

        <?php if ($show_otp ?? false): ?>
        <!-- OTP Form -->
        <form method="POST">
            <div class="form-group">
                <label>ENTER 6-DIGIT OTP</label>
                <input type="text" name="otp" class="otp-input"
                       maxlength="6" pattern="[0-9]{6}"
                       required placeholder="000000" autofocus>
            </div>
            <p class="otp-hint">📧 Check your email — code expires in 10 minutes</p>
            <button type="submit" name="verify_otp" class="btn">✓ VERIFY & LOGIN</button>
        </form>
        <a href="login.php" class="back-link">← Back to login</a>

        <?php else: ?>
        <!-- Login Form -->
        <form method="POST">
            <div class="form-group">
                <label>USERNAME</label>
                <input type="text" name="username"
                       value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                       required placeholder="Enter username"
                       <?= $is_locked ? 'disabled' : 'autofocus' ?>>
            </div>
            <div class="form-group">
                <label>PASSWORD</label>
                <input type="password" name="password" required placeholder="Enter password"
                       <?= $is_locked ? 'disabled' : '' ?>>
            </div>

            <?php if ($attempts_used > 0 && !$is_locked): ?>
            <div class="attempts-bar">
                <?php for ($i = 0; $i < MAX_ATTEMPTS; $i++): ?>
                <span class="<?= $i < $attempts_used ? 'used' : '' ?>"></span>
                <?php endfor; ?>
            </div>
            <?php endif; ?>

            <button type="submit" name="login" class="btn" <?= $is_locked ? 'disabled' : '' ?>>
                <?= $is_locked ? '🔒 ACCOUNT LOCKED' : 'LOGIN →' ?>
            </button>
        </form>
        <p class="register-link">Don't have an account? <a href="register.php">Register here</a></p>
        <?php endif; ?>

    </div>
</div>
</body>
</html>