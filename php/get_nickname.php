<?php
/**
 * QA Tutoring - 외부 DB 닉네임 조회 API
 * 
 * jungyoul.com 서버에 업로드하여 사용
 * 경로 예: https://jungyoul.com/api/get_nickname.php?user_id=123
 * 
 * 보안: 허용된 도메인만 호출 가능 (CORS 제한)
 */

header('Content-Type: application/json; charset=utf-8');

// CORS: QA Tutoring 앱에서만 호출 허용
$allowed_origins = [
    'https://qa-tutoring-app.pages.dev',
    'https://credit-planner-v8.pages.dev'
];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    // Cloudflare Workers는 Origin 헤더 없이 fetch하므로 허용
    header("Access-Control-Allow-Origin: *");
}
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Max-Age: 86400');

// OPTIONS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// GET만 허용
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// user_id 파라미터 검증
$user_id = isset($_GET['user_id']) ? intval($_GET['user_id']) : 0;
if ($user_id <= 0) {
    http_response_code(400);
    echo json_encode(['error' => 'user_id is required and must be a positive integer']);
    exit;
}

// MySQL 접속
$conn = new mysqli('localhost', 'jysk', 'jysk', 'jysk');

if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed']);
    exit;
}

$conn->set_charset('utf8mb4');

// nick_name 조회
$stmt = $conn->prepare('SELECT nick_name FROM User WHERE user_id = ?');
$stmt->bind_param('i', $user_id);
$stmt->execute();
$result = $stmt->get_result();
$row = $result->fetch_assoc();

$stmt->close();
$conn->close();

if ($row && $row['nick_name']) {
    echo json_encode([
        'success' => true,
        'user_id' => $user_id,
        'nick_name' => $row['nick_name']
    ], JSON_UNESCAPED_UNICODE);
} else {
    echo json_encode([
        'success' => false,
        'user_id' => $user_id,
        'nick_name' => null,
        'message' => 'User not found'
    ], JSON_UNESCAPED_UNICODE);
}
