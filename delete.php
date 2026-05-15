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

// Ownership check
$stmt = $conn->prepare("SELECT * FROM files WHERE id = ? AND user_id = ?");
$stmt->bind_param("ii", $file_id, $user_id);
$stmt->execute();
$file = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$file) {
    die("Access denied.");
}

// Delete physical file
if (file_exists($file['file_path'])) {
    unlink($file['file_path']);
}

// Delete shares
$del = $conn->prepare("DELETE FROM shares WHERE file_id = ?");
$del->bind_param("i", $file_id);
$del->execute();
$del->close();

// Delete from database
$stmt2 = $conn->prepare("DELETE FROM files WHERE id = ?");
$stmt2->bind_param("i", $file_id);
$stmt2->execute();
$stmt2->close();

// Log
$ip = $_SERVER['REMOTE_ADDR'] ?? '—';
$log = $conn->prepare("INSERT INTO logs (user_id, action, file_name, ip_address) VALUES (?, 'DELETE', ?, ?)");
$log->bind_param("iss", $user_id, $file['file_name'], $ip);
$log->execute();
$log->close();

header("Location: dashboard.php");
exit();
?>