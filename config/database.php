<?php

$host     = "127.0.0.1";
$dbname   = "secure_file_system";
$username = "root";
$password = "";

$conn = new mysqli($host, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

define('ENCRYPT_KEY', hash('sha256', 'MySecretPhrase#ChangeThis2024!'));

// Email config for 2FA
define('MAIL_HOST',     'smtp.gmail.com');
define('MAIL_PORT',     587);
define('MAIL_USERNAME', 'rushenfer123@gmail.com');
define('MAIL_PASSWORD', 'cgjdpikwikubkylk');
define('MAIL_FROM',     'rushenfer123@gmail.com');

?>