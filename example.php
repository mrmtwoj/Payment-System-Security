<?php
/**
 * PHP Payment Security Vulnerability Examples and Fixes (PHP 8.x)
 * Each section demonstrates a vulnerability, followed by simple and advanced fixes.
 */

/* ======================================================= */
/* === A1. SQL Injection === */
/* ======================================================= */

// === VULNERABLE CODE ===
$id = $_GET['id'];
$conn = new mysqli("localhost", "root", "", "payment_db");
$sql = "SELECT * FROM transactions WHERE id = $id"; // Unsafe
$result = $conn->query($sql);
while ($row = $result->fetch_assoc()) {
    echo "Transaction ID: " . $row['id'] . "<br>Amount: " . $row['amount'] . "<br>";
}

// === SIMPLE FIX ===
$stmt = $conn->prepare("SELECT * FROM transactions WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    echo "Transaction ID: " . $row['id'] . "<br>Amount: " . $row['amount'] . "<br>";
}

// === ADVANCED FIX ===
function validateTransactionId($input): int|null {
    return (filter_var($input, FILTER_VALIDATE_INT) !== false) ? (int)$input : null;
}
$validatedId = validateTransactionId($_GET['id'] ?? '');
if ($validatedId === null) {
    http_response_code(400);
    echo "Invalid Transaction ID.";
    exit;
}
$stmt = $conn->prepare("SELECT * FROM transactions WHERE id = ?");
$stmt->bind_param("i", $validatedId);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    echo "Transaction ID: " . htmlspecialchars($row['id']) . "<br>Amount: " . htmlspecialchars($row['amount']) . "<br>";
}

/* SQL TABLE */
CREATE TABLE `transactions` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `amount` DECIMAL(10,2) NOT NULL,
  `user_id` INT UNSIGNED NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

/* ======================================================= */
/* === A2. Cross-Site Scripting (XSS) === */
/* ======================================================= */

// === VULNERABLE CODE ===
echo "<div>User Comment: " . $_GET['comment'] . "</div>"; // Unsafe

// === SIMPLE FIX ===
echo "<div>User Comment: " . htmlspecialchars($_GET['comment']) . "</div>";

// === ADVANCED FIX ===
function sanitizeHtml($input): string {
    return htmlspecialchars(strip_tags($input), ENT_QUOTES, 'UTF-8');
}
echo "<div>User Comment: " . sanitizeHtml($_GET['comment']) . "</div>";

/* ======================================================= */
/* === A3. Cross-Site Request Forgery (CSRF) === */
/* ======================================================= */

// === VULNERABLE CODE ===
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $balance = $_POST['balance'];
    // Process without verifying request origin
}

// === SIMPLE FIX ===
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST' && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    $balance = $_POST['balance'];
    // Process securely
}

// === ADVANCED FIX ===
function generateCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken(string $token): bool {
    return hash_equals($_SESSION['csrf_token'], $token);
}

$csrfToken = generateCsrfToken();
if ($_SERVER['REQUEST_METHOD'] === 'POST' && validateCsrfToken($_POST['csrf_token'])) {
    $balance = $_POST['balance'];
}

/* ======================================================= */
/* === A4. Session Hijacking === */
/* ======================================================= */

// === VULNERABLE CODE ===
session_start();
$_SESSION['user'] = $userId; // Session fixated

// === SIMPLE FIX ===
session_start();
session_regenerate_id(true); // Prevent session fixation
$_SESSION['user'] = $userId;

// === ADVANCED FIX ===
session_set_cookie_params([
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();
session_regenerate_id(true);
$_SESSION['user'] = $userId;

/* ======================================================= */
/* === A5. Command Injection === */
/* ======================================================= */

// === VULNERABLE CODE ===
$filename = $_GET['file'];
system("cat uploads/$filename");

// === SIMPLE FIX ===
$whitelist = ['file1.txt', 'file2.txt'];
if (in_array($filename, $whitelist)) {
    system("cat uploads/$filename");
}

// === ADVANCED FIX ===
$filename = basename($_GET['file']);
$path = realpath("uploads/$filename");
if (strpos($path, realpath("uploads/")) === 0 && file_exists($path)) {
    echo file_get_contents($path);
}

/* ======================================================= */
/* === A6. Weak Password Storage === */
/* ======================================================= */

// === VULNERABLE CODE ===
$password = $_POST['password'];
$stored = $password; // Plain text storage

// === SIMPLE FIX ===
$stored = password_hash($password, PASSWORD_DEFAULT);

// === ADVANCED FIX ===
$options = ['cost' => 12];
$stored = password_hash($password, PASSWORD_BCRYPT, $options);
if (password_verify($_POST['password'], $stored)) {
    echo "Login success";
}

/* ======================================================= */
/* === A7. Insecure Transport Layer === */
/* ======================================================= */

// === VULNERABLE ===
// Sending credentials over HTTP

// === FIX ===
// Enforce HTTPS in server config (.htaccess or nginx)
// Example .htaccess:
// RewriteCond %{HTTPS} off
// RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

// Enable HSTS:
// header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

/* ======================================================= */
/* === A8. Brute Force (Lack of Rate Limiting) === */
/* ======================================================= */

// === VULNERABLE ===
// Unlimited login attempts with no lockout

// === SIMPLE FIX ===
// Count attempts in session and delay after 3
if (!isset($_SESSION['attempts'])) $_SESSION['attempts'] = 0;
$_SESSION['attempts']++;
if ($_SESSION['attempts'] > 3) sleep(5);

// === ADVANCED FIX ===
// Store attempts per IP or user in database, with timestamp
CREATE TABLE login_attempts (
    ip VARCHAR(45),
    attempts INT DEFAULT 0,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
// Query/update this table to limit requests
