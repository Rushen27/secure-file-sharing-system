<?php
session_start();
include "config/database.php";

$message = '';

if (isset($_POST['register'])) {

    // Get form data
    $username = trim($_POST['username']);
    $email    = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm  = $_POST['confirm'];

    // Check if passwords match
    if ($password !== $confirm) {
        $message = "Passwords do not match!";

    // Check password length
    } elseif (strlen($password) < 6) {
        $message = "Password must be at least 6 characters!";

    } else {

        // Check if username already exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $message = "Username or email already exists!";
        } else {

            // Hash the password — never store plain passwords!
            $hashed = password_hash($password, PASSWORD_BCRYPT);

            // Insert new user
            $stmt2 = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            $stmt2->bind_param("sss", $username, $email, $hashed);
            $stmt2->execute();
            $stmt2->close();

            // Redirect to login
            header("Location: login.php?registered=1");
            exit();
        }
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register — SecureShare</title>
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
            max-width: 420px;
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
        .card-header h1 {
            font-family: var(--mono);
            font-size: 0.95rem;
            font-weight: 600;
            letter-spacing: 0.04em;
        }
        .card-body { padding: 1.75rem; }
        .alert {
            font-family: var(--mono);
            font-size: 0.78rem;
            padding: 0.85rem 1rem;
            border-radius: 4px;
            margin-bottom: 1.25rem;
            background: rgba(255,71,87,0.08);
            border: 1px solid rgba(255,71,87,0.3);
            color: var(--danger);
        }
        .form-group { margin-bottom: 1.1rem; }
        label {
            display: block;
            font-family: var(--mono);
            font-size: 0.7rem;
            color: var(--muted);
            letter-spacing: 0.07em;
            margin-bottom: 0.4rem;
        }
        input {
            width: 100%;
            padding: 0.75rem 1rem;
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border);
            border-radius: 4px;
            color: var(--text);
            font-family: var(--mono);
            font-size: 0.82rem;
            transition: border-color 0.2s;
        }
        input:focus { outline: none; border-color: var(--accent2); }
        .btn {
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
            margin-top: 0.5rem;
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.9; }
        .login-link {
            display: block;
            text-align: center;
            margin-top: 1.25rem;
            font-family: var(--mono);
            font-size: 0.75rem;
            color: var(--muted);
            text-decoration: none;
        }
        .login-link a { color: var(--accent); text-decoration: none; }
        .login-link a:hover { text-decoration: underline; }
    </style>
</head>
<body>
<div class="card">
    <div class="card-header">
        <div class="icon">👤</div>
        <h1>CREATE_ACCOUNT</h1>
    </div>
    <div class="card-body">

        <?php if ($message): ?>
        <div class="alert">✕ <?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <form method="POST">
            <div class="form-group">
                <label>USERNAME</label>
                <input type="text" name="username" required placeholder="Enter username">
            </div>
            <div class="form-group">
                <label>EMAIL</label>
                <input type="email" name="email" required placeholder="Enter email">
            </div>
            <div class="form-group">
                <label>PASSWORD</label>
                <input type="password" name="password" required placeholder="Min 6 characters">
            </div>
            <div class="form-group">
                <label>CONFIRM PASSWORD</label>
                <input type="password" name="confirm" required placeholder="Repeat password">
            </div>
            <button type="submit" name="register" class="btn">CREATE ACCOUNT</button>
        </form>

        <p class="login-link">Already have an account? <a href="login.php">Login here</a></p>

    </div>
</div>
</body>
</html>