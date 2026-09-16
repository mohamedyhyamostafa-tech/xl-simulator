<?php
/**
 * ZAEEM DB ULTRA — PHP Edition (2026)
 * ------------------------------------------------------------
 * صفحة واحدة، بنمط OOP كامل + AJAX (بدون إعادة تحميل).
 * قاعدة البيانات: SQLite مدمجة داخل PHP (بدون سيرفر خارجي) مع فهارس
 * حقيقية و Pagination على مستوى SQL — الحل الوحيد الواقعي للسرعة مع
 * كميات بيانات ضخمة.
 * ------------------------------------------------------------
 */

declare(strict_types=1);

// ---- تقوية الجلسة قبل بدء الـ session ----
$__zdbSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['SERVER_PORT'] ?? '') == 443);
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/', 'domain' => '',
    'secure' => $__zdbSecure, 'httponly' => true, 'samesite' => 'Strict',
]);
ini_set('session.use_strict_mode', '1');
session_start();
mb_internal_encoding('UTF-8');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');

if (!extension_loaded('sodium')) {
    http_response_code(500);
    exit('يتطلب هذا التطبيق امتداد PHP sodium لتشفير بيانات الدخول. فعّله من إعدادات السيرفر (php.ini).');
}

// ==================================================================
//  CONFIG / PATHS
// ==================================================================
final class Config
{
    public const APP_NAME    = 'ZAEEM DB ULTRA';
    public const APP_VERSION = 'v2026 PHP Edition';
    public const PAGE_SIZES  = [50, 100, 500, 1000, 5000, 10000, 50000];
    public const DEFAULT_PAGE_SIZE = 500;

    public static string $baseDir;
    public static string $dataDir;
    public static string $configDir;

    public static function init(): void
    {
        self::$baseDir   = __DIR__;
        self::$dataDir   = self::$baseDir . '/zdb_data';
        self::$configDir = self::$baseDir . '/zdb_config';
        if (!is_dir(self::$dataDir))   { @mkdir(self::$dataDir, 0770, true); }
        if (!is_dir(self::$configDir)) { @mkdir(self::$configDir, 0770, true); }
        foreach ([self::$dataDir, self::$configDir] as $dir) {
            $ht = $dir . '/.htaccess';
            if (!file_exists($ht)) { @file_put_contents($ht, "Require all denied\nDeny from all\n"); }
        }
    }
}
Config::init();

// ==================================================================
//  SECURITY — تجزئة كلمة المرور (one-way, غير قابلة للاسترجاع)
// ==================================================================
final class Security
{
    public static function hash(string $plain): string
    {
        return password_hash($plain, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    public static function verify(string $plain, string $hash): bool
    {
        return password_verify($plain, $hash);
    }
}

/**
 * SecurityVault — الخزنة المشفّرة
 * ------------------------------------------------------------
 * كل بيانات الدخول (اسم المستخدم/كلمة المرور المجزّأة) وسجل محاولات
 * القفل تُخزَّن مشفّرة بالكامل (XSalsa20-Poly1305 عبر libsodium) —
 * تشفير موثّق (Authenticated Encryption)، فلو حد لمس أو عدّل الملف
 * مباشرة، فك التشفير يفشل فوراً ويُكتشف العبث. المفتاح 32 بايت يُولَّد
 * عشوائياً أول مرة ويُحفظ بصلاحيات 600 فقط (قراءة/كتابة للمالك فقط)
 * فى ملف منفصل عن ملف البيانات، وكلاهما محميان بـ .htaccess (Deny all)
 * ولا يمكن الوصول إليهما مباشرة من المتصفح.
 * القفل بعد المحاولات الفاشلة مرتبط ببصمة (IP + User-Agent) وليس
 * بالجلسة أو الكوكيز، فمسح الكوكيز أو فتح تصفح خفي لا يتخطى القفل.
 */
final class SecurityVault
{
    private string $keyFile;
    private string $credsFile;
    private string $lockFile;
    private string $key;

    private const LOCK_STEPS = [0, 0, 0, 5, 15, 60, 300, 900, 3600];

    public function __construct()
    {
        $this->keyFile   = Config::$configDir . '/.vk';
        $this->credsFile = Config::$configDir . '/.vd';
        $this->lockFile  = Config::$configDir . '/.vl';
        $this->key       = $this->loadOrCreateKey();
    }

    private function loadOrCreateKey(): string
    {
        if (file_exists($this->keyFile)) {
            $k = (string) file_get_contents($this->keyFile);
            if (strlen($k) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES) return $k;
        }
        $k = sodium_crypto_secretbox_keygen();
        file_put_contents($this->keyFile, $k);
        @chmod($this->keyFile, 0600);
        return $k;
    }

    private function encrypt(array $data): string
    {
        $nonce  = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = sodium_crypto_secretbox(json_encode($data), $nonce, $this->key);
        return base64_encode($nonce . $cipher);
    }

    private function decrypt(string $blob): ?array
    {
        $raw = base64_decode($blob, true);
        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) return null;
        $nonce  = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plain  = sodium_crypto_secretbox_open($cipher, $nonce, $this->key);
        if ($plain === false) return null; // تلاعب أو تلف فى الملف
        $j = json_decode($plain, true);
        return is_array($j) ? $j : null;
    }

    private function readEncrypted(string $path): ?array
    {
        if (!file_exists($path)) return null;
        return $this->decrypt((string) file_get_contents($path));
    }

    private function writeEncrypted(string $path, array $data): void
    {
        file_put_contents($path, $this->encrypt($data));
        @chmod($path, 0600);
    }

    public function loadCreds(): array
    {
        $data = $this->readEncrypted($this->credsFile);
        if ($data === null || !isset($data['user'], $data['pass'])) {
            $default = ['user' => Security::hash('root'), 'pass' => Security::hash('0000')];
            $this->writeEncrypted($this->credsFile, $default);
            return $default;
        }
        return $data;
    }

    public function saveCreds(string $userHash, string $passHash): void
    {
        $this->writeEncrypted($this->credsFile, ['user' => $userHash, 'pass' => $passHash]);
    }

    private function fingerprint(): string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        return hash('sha256', $ip . '|' . $ua);
    }

    private function loadLocks(): array
    {
        return $this->readEncrypted($this->lockFile) ?? [];
    }

    private function saveLocks(array $locks): void
    {
        $now = time();
        foreach ($locks as $k => $rec) {
            if (($rec['locked_until'] ?? 0) < $now - 86400) unset($locks[$k]);
        }
        $this->writeEncrypted($this->lockFile, $locks);
    }

    /** ثوانى القفل المتبقية، أو صفر لو مش مقفول */
    public function isLocked(): int
    {
        $rec = $this->loadLocks()[$this->fingerprint()] ?? null;
        $remain = ($rec['locked_until'] ?? 0) - time();
        return $remain > 0 ? $remain : 0;
    }

    public function registerFailure(): int
    {
        $locks = $this->loadLocks();
        $fp    = $this->fingerprint();
        $rec   = $locks[$fp] ?? ['attempts' => 0, 'locked_until' => 0];
        $rec['attempts']++;
        $idx  = min($rec['attempts'], count(self::LOCK_STEPS) - 1);
        $lock = self::LOCK_STEPS[$idx];
        if ($lock > 0) $rec['locked_until'] = time() + $lock;
        $locks[$fp] = $rec;
        $this->saveLocks($locks);
        return $lock;
    }

    public function registerSuccess(): void
    {
        $locks = $this->loadLocks();
        unset($locks[$this->fingerprint()]);
        $this->saveLocks($locks);
    }
}

// ==================================================================
//  AUTH MANAGER
// ==================================================================
final class AuthManager
{
    private SecurityVault $vault;
    private array $creds;

    public function __construct()
    {
        $this->vault = new SecurityVault();
        $this->creds = $this->vault->loadCreds();
    }

    public function isLoggedIn(): bool
    {
        return !empty($_SESSION['zdb_auth']);
    }

    public function login(string $user, string $pass): array
    {
        $remain = $this->vault->isLocked();
        if ($remain > 0) {
            return ['ok' => false, 'msg' => "محاولات كثيرة. الحساب مقفول لمدة {$remain} ثانية"];
        }

        // لا يوجد short-circuit — كلا الفحصين ينفذان دائماً (مقاومة هجمات التوقيت)
        $userOk = Security::verify($user, $this->creds['user']);
        $passOk = Security::verify($pass, $this->creds['pass']);

        if ($userOk && $passOk) {
            session_regenerate_id(true);
            $_SESSION['zdb_auth'] = true;
            $this->vault->registerSuccess();
            return ['ok' => true];
        }

        $lock = $this->vault->registerFailure();
        if ($lock > 0) {
            return ['ok' => false, 'msg' => "بيانات خاطئة. تم القفل لمدة {$lock} ثانية"];
        }
        return ['ok' => false, 'msg' => 'اسم المستخدم أو كلمة المرور غير صحيحة'];
    }

    public function changeCredentials(string $user, string $pass): void
    {
        $this->vault->saveCreds(Security::hash($user), Security::hash($pass));
    }

    public function logout(): void
    {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
        }
        session_destroy();
    }
}

// ==================================================================
//  SAFE MATH EXPRESSION EVALUATOR (بدون eval() لأسباب أمنية)
// ==================================================================
final class MathEvaluator
{
    private array $tokens = [];
    private int $pos = 0;
    private float $x = 0.0;

    private const FUNCS  = ['sin', 'cos', 'tan', 'log', 'log10', 'exp', 'sqrt', 'abs'];
    private const CONSTS = ['pi' => M_PI, 'e' => M_E];

    public function evaluate(string $expr, float $x): float
    {
        $this->x = $x;
        $this->tokens = $this->tokenize($expr);
        $this->pos = 0;
        return $this->parseExpr();
    }

    private function tokenize(string $s): array
    {
        $toks = []; $len = strlen($s); $i = 0;
        while ($i < $len) {
            $c = $s[$i];
            if ($c === ' ' || $c === "\t") { $i++; continue; }
            if (ctype_digit($c) || $c === '.') {
                $j = $i;
                while ($j < $len && (ctype_digit($s[$j]) || $s[$j] === '.')) $j++;
                $toks[] = ['num', (float) substr($s, $i, $j - $i)];
                $i = $j; continue;
            }
            if (ctype_alpha($c) || $c === '_') {
                $j = $i;
                while ($j < $len && (ctype_alnum($s[$j]) || $s[$j] === '_')) $j++;
                $toks[] = ['id', substr($s, $i, $j - $i)];
                $i = $j; continue;
            }
            if ($c === '*' && $i + 1 < $len && $s[$i + 1] === '*') { $toks[] = ['op', '**']; $i += 2; continue; }
            if (strpos('+-*/(),', $c) !== false) { $toks[] = ['op', $c]; $i++; continue; }
            $i++;
        }
        return $toks;
    }

    private function peek() { return $this->tokens[$this->pos] ?? null; }
    private function next() { return $this->tokens[$this->pos++] ?? null; }

    private function parseExpr(): float
    {
        $val = $this->parseTerm();
        while (($t = $this->peek()) && $t[0] === 'op' && ($t[1] === '+' || $t[1] === '-')) {
            $this->next();
            $rhs = $this->parseTerm();
            $val = $t[1] === '+' ? $val + $rhs : $val - $rhs;
        }
        return $val;
    }

    private function parseTerm(): float
    {
        $val = $this->parsePower();
        while (($t = $this->peek()) && $t[0] === 'op' && ($t[1] === '*' || $t[1] === '/')) {
            $this->next();
            $rhs = $this->parsePower();
            $val = $t[1] === '*' ? $val * $rhs : ($rhs == 0.0 ? NAN : $val / $rhs);
        }
        return $val;
    }

    private function parsePower(): float
    {
        $val = $this->parseUnary();
        if (($t = $this->peek()) && $t[0] === 'op' && $t[1] === '**') {
            $this->next();
            $val = $val ** $this->parsePower();
        }
        return $val;
    }

    private function parseUnary(): float
    {
        $t = $this->peek();
        if ($t && $t[0] === 'op' && $t[1] === '-') { $this->next(); return -$this->parseUnary(); }
        if ($t && $t[0] === 'op' && $t[1] === '+') { $this->next(); return $this->parseUnary(); }
        return $this->parseAtom();
    }

    private function parseAtom(): float
    {
        $t = $this->next();
        if (!$t) return 0.0;
        if ($t[0] === 'num') return (float) $t[1];
        if ($t[0] === 'id') {
            $name = $t[1];
            if ($name === 'x') return $this->x;
            if (isset(self::CONSTS[$name])) return self::CONSTS[$name];
            if (in_array($name, self::FUNCS, true)) {
                $this->expect('(');
                $arg = $this->parseExpr();
                $this->expect(')');
                return match ($name) {
                    'sin'   => sin($arg),
                    'cos'   => cos($arg),
                    'tan'   => tan($arg),
                    'log'   => $arg > 0 ? log($arg) : NAN,
                    'log10' => $arg > 0 ? log10($arg) : NAN,
                    'exp'   => exp($arg),
                    'sqrt'  => $arg >= 0 ? sqrt($arg) : NAN,
                    'abs'   => abs($arg),
                    default => NAN,
                };
            }
            return 0.0;
        }
        if ($t[0] === 'op' && $t[1] === '(') {
            $v = $this->parseExpr();
            $this->expect(')');
            return $v;
        }
        return 0.0;
    }

    private function expect(string $op): void
    {
        $t = $this->next();
        if (!$t || $t[0] !== 'op' || $t[1] !== $op) {
            throw new RuntimeException("صيغة رياضية غير صحيحة، متوقع '{$op}'");
        }
    }
}

// ==================================================================
//  DATABASE MANAGER — كل "قاعدة بيانات" = ملف SQLite مستقل
// ==================================================================
final class DatabaseManager
{
    public static function sanitizeName(string $name): string
    {
        $name = trim($name);
        $name = preg_replace('/[^\p{L}\p{N}_\-\s]/u', '', $name) ?? '';
        if ($name === '') throw new InvalidArgumentException('اسم غير صالح');
        return $name;
    }

    public static function pathFor(string $dbName): string
    {
        return Config::$dataDir . '/' . self::sanitizeName($dbName) . '.sqlite';
    }

    public static function list(): array
    {
        $out = [];
        foreach (glob(Config::$dataDir . '/*.sqlite') ?: [] as $f) $out[] = basename($f, '.sqlite');
        sort($out, SORT_FLAG_CASE | SORT_STRING);
        return $out;
    }

    public static function create(string $name): void
    {
        $path = self::pathFor($name);
        if (file_exists($path)) throw new RuntimeException('قاعدة البيانات موجودة بالفعل');
        $pdo = self::connect($name);
        $pdo->exec('CREATE TABLE IF NOT EXISTS __zdb_meta__ (k TEXT PRIMARY KEY, v TEXT)');
    }

    public static function delete(string $name): void
    {
        $path = self::pathFor($name);
        if (file_exists($path)) unlink($path);
        foreach (['-wal', '-shm'] as $suf) if (file_exists($path . $suf)) unlink($path . $suf);
    }

    public static function rename(string $old, string $new): void
    {
        $oldPath = self::pathFor($old);
        $newPath = self::pathFor($new);
        if (!file_exists($oldPath)) throw new RuntimeException('غير موجودة');
        if (file_exists($newPath)) throw new RuntimeException('الاسم الجديد مستخدم بالفعل');
        rename($oldPath, $newPath);
    }

    public static function connect(string $dbName): PDO
    {
        $path = self::pathFor($dbName);
        $pdo = new PDO('sqlite:' . $path);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec('PRAGMA journal_mode = WAL');
        $pdo->exec('PRAGMA synchronous = NORMAL');
        $pdo->exec('PRAGMA temp_store = MEMORY');
        $pdo->exec('PRAGMA cache_size = -64000');
        return $pdo;
    }
}

// ==================================================================
//  TABLE MANAGER
// ==================================================================
final class TableManager
{
    private PDO $pdo;
    private string $table;

    public function __construct(private string $dbName, string $tableName)
    {
        $this->pdo = DatabaseManager::connect($dbName);
        $this->table = $this->quoteIdentSafe($tableName);
    }

    private function quoteIdentSafe(string $name): string
    {
        $clean = preg_replace('/[^\p{L}\p{N}_]/u', '_', trim($name)) ?? '';
        if ($clean === '') throw new InvalidArgumentException('اسم غير صالح');
        if (preg_match('/^[0-9]/', $clean)) $clean = 't_' . $clean;
        return $clean;
    }

    public static function listTables(string $dbName): array
    {
        $pdo = DatabaseManager::connect($dbName);
        $stmt = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '\_\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite_%'");
        $out = [];
        foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $n) $out[] = $n;
        sort($out, SORT_FLAG_CASE | SORT_STRING);
        return $out;
    }

    public static function create(string $dbName, string $tableName, array $columns): void
    {
        $tm = new self($dbName, $tableName);
        $cols = array_map(fn($c) => $tm->quoteIdentSafe($c), $columns);
        $colsSql = implode(', ', array_map(fn($c) => "\"$c\" TEXT", $cols));
        $tm->pdo->exec("CREATE TABLE IF NOT EXISTS \"{$tm->table}\" (__rid__ INTEGER PRIMARY KEY AUTOINCREMENT, $colsSql)");
        $tm->pdo->exec("CREATE TABLE IF NOT EXISTS \"{$tm->table}__colors\" (row_id INTEGER, target TEXT, color TEXT, PRIMARY KEY(row_id, target))");
    }

    public static function delete(string $dbName, string $tableName): void
    {
        $tm = new self($dbName, $tableName);
        $tm->pdo->exec("DROP TABLE IF EXISTS \"{$tm->table}\"");
        $tm->pdo->exec("DROP TABLE IF EXISTS \"{$tm->table}__colors\"");
    }

    public static function rename(string $dbName, string $old, string $new): void
    {
        $tm = new self($dbName, $old);
        $newSafe = $tm->quoteIdentSafe($new);
        $tm->pdo->exec("ALTER TABLE \"{$tm->table}\" RENAME TO \"{$newSafe}\"");
        try { $tm->pdo->exec("ALTER TABLE \"{$tm->table}__colors\" RENAME TO \"{$newSafe}__colors\""); } catch (Throwable $e) {}
    }

    public function columns(): array
    {
        $stmt = $this->pdo->query("PRAGMA table_info(\"{$this->table}\")");
        $out = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) { if ($r['name'] !== '__rid__') $out[] = $r['name']; }
        return $out;
    }

    public function addColumn(string $name): void
    {
        $safe = $this->quoteIdentSafe($name);
        $this->pdo->exec("ALTER TABLE \"{$this->table}\" ADD COLUMN \"{$safe}\" TEXT");
    }

    public function renameColumn(string $old, string $new): void
    {
        $o = $this->quoteIdentSafe($old); $n = $this->quoteIdentSafe($new);
        $this->pdo->exec("ALTER TABLE \"{$this->table}\" RENAME COLUMN \"{$o}\" TO \"{$n}\"");
    }

    public function deleteColumn(string $name): void
    {
        $safe = $this->quoteIdentSafe($name);
        $this->pdo->exec("ALTER TABLE \"{$this->table}\" DROP COLUMN \"{$safe}\"");
    }

    public function clear(): void
    {
        $this->pdo->exec("DELETE FROM \"{$this->table}\"");
        $this->pdo->exec("DELETE FROM \"{$this->table}__colors\"");
        $this->pdo->exec("DELETE FROM sqlite_sequence WHERE name = '{$this->table}'");
    }

    private function buildWhere(string $search, array $cols): array
    {
        if ($search === '') return ['', []];
        $parts = []; $params = [];
        foreach ($cols as $i => $c) { $parts[] = "CAST(\"$c\" AS TEXT) LIKE :s{$i}"; $params[":s{$i}"] = '%' . $search . '%'; }
        return [' WHERE ' . implode(' OR ', $parts), $params];
    }

    public function count(string $search = ''): int
    {
        $cols = $this->columns();
        [$where, $params] = $this->buildWhere($search, $cols);
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM \"{$this->table}\"{$where}");
        $stmt->execute($params);
        return (int) $stmt->fetchColumn();
    }

    public function getPage(int $page, int $pageSize, string $search = '', array $sort = []): array
    {
        $cols = $this->columns();
        [$where, $params] = $this->buildWhere($search, $cols);

        $orderSql = '';
        if ($sort) {
            $parts = [];
            foreach ($sort as $s) {
                $c = $this->quoteIdentSafe($s['col']);
                if (!in_array($c, $cols, true)) continue;
                $dir = strtoupper($s['dir'] ?? 'ASC') === 'DESC' ? 'DESC' : 'ASC';
                $parts[] = !empty($s['numeric']) ? "CAST(\"$c\" AS REAL) $dir" : "\"$c\" COLLATE NOCASE $dir";
            }
            if ($parts) $orderSql = ' ORDER BY ' . implode(', ', $parts);
        } else {
            $orderSql = ' ORDER BY __rid__ ASC';
        }

        $offset = max(0, $page) * $pageSize;
        $selectCols = '__rid__,' . implode(',', array_map(fn($c) => "\"$c\"", $cols));
        $sql = "SELECT {$selectCols} FROM \"{$this->table}\"{$where}{$orderSql} LIMIT :lim OFFSET :off";
        $stmt = $this->pdo->prepare($sql);
        foreach ($params as $k => $v) $stmt->bindValue($k, $v, PDO::PARAM_STR);
        $stmt->bindValue(':lim', $pageSize, PDO::PARAM_INT);
        $stmt->bindValue(':off', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $colorMap = [];
        $rids = array_column($rows, '__rid__');
        if ($rids) {
            $in = implode(',', array_fill(0, count($rids), '?'));
            $cstmt = $this->pdo->prepare("SELECT row_id, color FROM \"{$this->table}__colors\" WHERE target='row' AND row_id IN ($in)");
            $cstmt->execute($rids);
            foreach ($cstmt->fetchAll(PDO::FETCH_ASSOC) as $r) $colorMap[$r['row_id']] = $r['color'];
        }
        foreach ($rows as &$r) $r['__color__'] = $colorMap[$r['__rid__']] ?? null;
        return ['rows' => $rows, 'columns' => $cols];
    }

    public function insertRow(array $data): int
    {
        $cols = $this->columns();
        $vals = [];
        foreach ($cols as $c) $vals[$c] = $data[$c] ?? '';
        $names = implode(',', array_map(fn($c) => "\"$c\"", array_keys($vals)));
        $ph = implode(',', array_map(fn($c) => ":$c", array_keys($vals)));
        $stmt = $this->pdo->prepare("INSERT INTO \"{$this->table}\" ($names) VALUES ($ph)");
        foreach ($vals as $k => $v) $stmt->bindValue(":$k", $v, PDO::PARAM_STR);
        $stmt->execute();
        return (int) $this->pdo->lastInsertId();
    }

    public function updateRow(int $rid, array $data): void
    {
        $cols = $this->columns();
        $sets = []; $vals = [];
        foreach ($cols as $c) { if (array_key_exists($c, $data)) { $sets[] = "\"$c\" = :$c"; $vals[":$c"] = $data[$c]; } }
        if (!$sets) return;
        $stmt = $this->pdo->prepare("UPDATE \"{$this->table}\" SET " . implode(',', $sets) . " WHERE __rid__ = :rid");
        foreach ($vals as $k => $v) $stmt->bindValue($k, $v, PDO::PARAM_STR);
        $stmt->bindValue(':rid', $rid, PDO::PARAM_INT);
        $stmt->execute();
    }

    public function deleteRows(array $rids): int
    {
        if (!$rids) return 0;
        $in = implode(',', array_fill(0, count($rids), '?'));
        $stmt = $this->pdo->prepare("DELETE FROM \"{$this->table}\" WHERE __rid__ IN ($in)");
        $stmt->execute($rids);
        $stmt2 = $this->pdo->prepare("DELETE FROM \"{$this->table}__colors\" WHERE row_id IN ($in)");
        $stmt2->execute($rids);
        return $stmt->rowCount();
    }

    public function setRowColor(int $rid, string $color): void
    {
        $stmt = $this->pdo->prepare("INSERT INTO \"{$this->table}__colors\" (row_id, target, color) VALUES (?, 'row', ?)
            ON CONFLICT(row_id, target) DO UPDATE SET color = excluded.color");
        $stmt->execute([$rid, $color]);
    }

    public function colorRowsMatching(string $col, string $needle, string $color): int
    {
        $c = $this->quoteIdentSafe($col);
        $stmt = $this->pdo->prepare("SELECT __rid__ FROM \"{$this->table}\" WHERE CAST(\"$c\" AS TEXT) LIKE ?");
        $stmt->execute(['%' . $needle . '%']);
        $rids = $stmt->fetchAll(PDO::FETCH_COLUMN);
        $this->pdo->beginTransaction();
        foreach ($rids as $rid) $this->setRowColor((int) $rid, $color);
        $this->pdo->commit();
        return count($rids);
    }

    public function colorEntireColumn(string $col, string $color): void
    {
        $stmt = $this->pdo->prepare("INSERT INTO \"{$this->table}__colors\" (row_id, target, color) VALUES (-1, ?, ?)
            ON CONFLICT(row_id, target) DO UPDATE SET color = excluded.color");
        $stmt->execute(['col:' . $col, $color]);
    }

    public function columnColors(): array
    {
        $stmt = $this->pdo->query("SELECT target, color FROM \"{$this->table}__colors\" WHERE row_id = -1");
        $out = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) { if (str_starts_with($r['target'], 'col:')) $out[substr($r['target'], 4)] = $r['color']; }
        return $out;
    }

    public function clearColors(): void { $this->pdo->exec("DELETE FROM \"{$this->table}__colors\""); }

    public function persistSort(array $sort): void
    {
        $data = $this->getPage(0, 5_000_000, '', $sort);
        $rows = $data['rows']; $cols = $data['columns'];
        $this->pdo->beginTransaction();
        $this->pdo->exec("DELETE FROM \"{$this->table}\"");
        $names = implode(',', array_map(fn($c) => "\"$c\"", $cols));
        $ph = implode(',', array_fill(0, count($cols), '?'));
        $stmt = $this->pdo->prepare("INSERT INTO \"{$this->table}\" ($names) VALUES ($ph)");
        foreach ($rows as $r) { $vals = []; foreach ($cols as $c) $vals[] = $r[$c]; $stmt->execute($vals); }
        $this->pdo->commit();
    }

    public function applyMath(string $col, string $formula, string $resultCol): array
    {
        $c = $this->quoteIdentSafe($col);
        $rc = $this->quoteIdentSafe($resultCol);
        if (!in_array($rc, $this->columns(), true)) $this->addColumn($resultCol);

        $ev = new MathEvaluator();
        $stmt = $this->pdo->query("SELECT __rid__, \"$c\" AS v FROM \"{$this->table}\"");
        $upd = $this->pdo->prepare("UPDATE \"{$this->table}\" SET \"$rc\" = :v WHERE __rid__ = :rid");
        $errors = 0; $count = 0;
        $this->pdo->beginTransaction();
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $raw = trim((string) $row['v']);
            if ($raw === '') continue;
            $num = str_replace(['٠','١','٢','٣','٤','٥','٦','٧','٨','٩'], ['0','1','2','3','4','5','6','7','8','9'], $raw);
            if (!is_numeric($num)) { $upd->execute([':v' => 'خطأ', ':rid' => $row['__rid__']]); $errors++; continue; }
            try {
                $res = $ev->evaluate($formula, (float) $num);
                $val = is_nan($res) || is_infinite($res) ? 'خطأ حسابي' : (string) round($res, 6);
            } catch (Throwable $e) { $val = 'خطأ'; $errors++; }
            $upd->execute([':v' => $val, ':rid' => $row['__rid__']]);
            $count++;
        }
        $this->pdo->commit();
        return ['applied' => $count, 'errors' => $errors, 'result_col' => $resultCol];
    }

    public function generate(string $pool, int $length, int $rows, string $mode, ?string $targetCol, ?string $newColName): array
    {
        if ($pool === '') throw new RuntimeException('مجموعة الرموز فارغة');
        $seen = []; $values = [];
        $maxAttempts = $rows * 50; $attempts = 0;
        $poolLen = mb_strlen($pool);
        while (count($values) < $rows && $attempts < $maxAttempts) {
            $v = '';
            for ($k = 0; $k < $length; $k++) $v .= mb_substr($pool, random_int(0, $poolLen - 1), 1);
            if (!isset($seen[$v])) { $seen[$v] = true; $values[] = $v; }
            $attempts++;
        }

        $this->pdo->beginTransaction();
        if ($mode === 'new_rows') {
            $col = $this->quoteIdentSafe($targetCol ?: ($newColName ?: 'generated'));
            if ($targetCol === null && !in_array($col, $this->columns(), true)) $this->addColumn($newColName ?: 'generated');
            $stmt = $this->pdo->prepare("INSERT INTO \"{$this->table}\" (\"$col\") VALUES (?)");
            foreach ($values as $v) $stmt->execute([$v]);
        } elseif ($mode === 'fill_existing' && $targetCol) {
            $col = $this->quoteIdentSafe($targetCol);
            $rids = $this->pdo->query("SELECT __rid__ FROM \"{$this->table}\" ORDER BY __rid__")->fetchAll(PDO::FETCH_COLUMN);
            $upd = $this->pdo->prepare("UPDATE \"{$this->table}\" SET \"$col\" = ? WHERE __rid__ = ?");
            foreach ($rids as $i => $rid) { if (!isset($values[$i])) break; $upd->execute([$values[$i], $rid]); }
        } else {
            $newName = $newColName ?: 'generated';
            $col = $this->quoteIdentSafe($newName);
            if (!in_array($col, $this->columns(), true)) $this->addColumn($newName);
            $rids = $this->pdo->query("SELECT __rid__ FROM \"{$this->table}\" ORDER BY __rid__")->fetchAll(PDO::FETCH_COLUMN);
            $upd = $this->pdo->prepare("UPDATE \"{$this->table}\" SET \"$col\" = ? WHERE __rid__ = ?");
            foreach ($rids as $i => $rid) { if (!isset($values[$i])) break; $upd->execute([$values[$i], $rid]); }
            $extra = array_slice($values, count($rids));
            if ($extra) { $ins = $this->pdo->prepare("INSERT INTO \"{$this->table}\" (\"$col\") VALUES (?)"); foreach ($extra as $v) $ins->execute([$v]); }
        }
        $this->pdo->commit();
        return ['generated' => count($values), 'requested' => $rows];
    }

    public function findDuplicates(array $cols, string $mode): array
    {
        $cols = array_map(fn($c) => $this->quoteIdentSafe($c), $cols);
        $keyExpr = implode(" || '\u{1F}' || ", array_map(fn($c) => "IFNULL(\"$c\",'')", $cols));

        if ($mode === 'delete') {
            $this->pdo->exec("DELETE FROM \"{$this->table}\" WHERE __rid__ NOT IN (SELECT MIN(__rid__) FROM \"{$this->table}\" GROUP BY $keyExpr)");
            return ['removed' => $this->pdo->query('SELECT changes()')->fetchColumn()];
        }
        if ($mode === 'count') {
            $selectCols = implode(',', array_map(fn($c) => "\"$c\"", $cols));
            $stmt = $this->pdo->query("SELECT $selectCols, COUNT(*) AS cnt FROM \"{$this->table}\" GROUP BY $keyExpr HAVING COUNT(*) > 1 LIMIT 10000");
            return ['rows' => $stmt->fetchAll(PDO::FETCH_ASSOC), 'columns' => array_merge($cols, ['cnt'])];
        }
        $having = $mode === 'unique' ? 'HAVING COUNT(*) = 1' : 'HAVING COUNT(*) > 1';
        $allCols = $this->columns();
        $selectAll = implode(',', array_map(fn($c) => "\"$c\"", $allCols));
        $stmt = $this->pdo->query("SELECT $selectAll FROM \"{$this->table}\" WHERE $keyExpr IN (SELECT $keyExpr FROM \"{$this->table}\" GROUP BY $keyExpr $having) LIMIT 10000");
        return ['rows' => $stmt->fetchAll(PDO::FETCH_ASSOC), 'columns' => $allCols];
    }

    public function importColumns(string $csvPath, array $selectedSrcCols, array $newNames, string $fillMode): array
    {
        if (!file_exists($csvPath)) throw new RuntimeException('ملف الاستيراد غير موجود');
        $fh = fopen($csvPath, 'r');
        $srcHeaders = fgetcsv($fh);
        if (!$srcHeaders) { fclose($fh); throw new RuntimeException('الملف فارغ'); }
        $idxMap = [];
        foreach ($selectedSrcCols as $sc) { $i = array_search($sc, $srcHeaders, true); if ($i !== false) $idxMap[$sc] = $i; }
        $srcRows = [];
        while (($r = fgetcsv($fh)) !== false) $srcRows[] = $r;
        fclose($fh);

        $finalNames = [];
        foreach ($selectedSrcCols as $i => $sc) $finalNames[] = ($newNames[$i] ?? '') !== '' ? $newNames[$i] : $sc;
        foreach ($finalNames as $fn) { if (!in_array($this->quoteIdentSafe($fn), $this->columns(), true)) $this->addColumn($fn); }

        $curRids = $this->pdo->query("SELECT __rid__ FROM \"{$this->table}\" ORDER BY __rid__")->fetchAll(PDO::FETCH_COLUMN);
        $curCount = count($curRids);
        $maxSrc = count($srcRows);
        $n = $fillMode === 'truncate' ? min($curCount, $maxSrc) : max($curCount, $maxSrc);

        $this->pdo->beginTransaction();
        for ($i = 0; $i < $n; $i++) {
            $vals = [];
            foreach ($selectedSrcCols as $j => $sc) {
                $srcIdx = $idxMap[$sc] ?? null;
                $vals[$finalNames[$j]] = ($srcIdx !== null && isset($srcRows[$i][$srcIdx])) ? $srcRows[$i][$srcIdx] : '';
            }
            if ($i < $curCount) $this->updateRow((int) $curRids[$i], $vals);
            else $this->insertRow($vals);
        }
        $this->pdo->commit();
        return ['imported_rows' => $n, 'columns' => $finalNames];
    }
}

// ==================================================================
//  EXPORTER
// ==================================================================
final class Exporter
{
    public static function csv(array $headers, array $rows): string
    {
        $fh = fopen('php://temp', 'r+');
        fputcsv($fh, $headers);
        foreach ($rows as $r) fputcsv($fh, $r);
        rewind($fh);
        $out = stream_get_contents($fh);
        fclose($fh);
        return "\xEF\xBB\xBF" . $out;
    }

    public static function txt(array $headers, array $rows): string
    {
        $out = implode("\t|\t", $headers) . "\n" . str_repeat('-', 60) . "\n";
        foreach ($rows as $r) $out .= implode("\t|\t", $r) . "\n";
        return $out;
    }

    public static function sql(array $headers, array $rows, string $tableName = 'exported_data'): string
    {
        $out = "CREATE TABLE IF NOT EXISTS `$tableName` (\n" . implode(",\n", array_map(fn($c) => "  `$c` TEXT", $headers)) . "\n);\n\n";
        foreach ($rows as $r) {
            $vals = array_map(fn($v) => "'" . str_replace("'", "''", (string) $v) . "'", $r);
            $out .= "INSERT INTO `$tableName` VALUES (" . implode(', ', $vals) . ");\n";
        }
        return $out;
    }

    public static function html(array $headers, array $rows): string
    {
        $th = implode('', array_map(fn($h) => '<th>' . htmlspecialchars((string) $h) . '</th>', $headers));
        $trs = '';
        foreach ($rows as $r) $trs .= '<tr>' . implode('', array_map(fn($v) => '<td>' . htmlspecialchars((string) $v) . '</td>', $r)) . "</tr>\n";
        return <<<HTML
<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>تقرير البيانات المصدّرة</title>
<style>
body{font-family:'Segoe UI',Tahoma,Arial,sans-serif;margin:40px;color:#333;background:#fff}
.header{background:#2e44ad;color:#fff;padding:25px;text-align:center;border-radius:6px;margin-bottom:30px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{background:#2e44ad;color:#fff;padding:12px;border:1px solid #dee2e6}
td{padding:10px;border:1px solid #dee2e6;text-align:center}
tr:nth-child(even){background:#f8f9fa}
.footer{margin-top:40px;text-align:center;font-size:12px;color:#777;border-top:1px solid #eee;padding-top:15px}
@media print{body{margin:20px}}
</style></head><body>
<div class="header"><h1>تقرير البيانات المصدّرة</h1></div>
<table><thead><tr>$th</tr></thead><tbody>$trs</tbody></table>
<div class="footer">تم التصدير تلقائياً — ZAEEM DB ULTRA</div>
<script>window.onload=function(){window.print();}</script>
</body></html>
HTML;
    }
}

// ==================================================================
//  API DISPATCHER
// ==================================================================
final class Api
{
    public function handle(string $action, array $req): array
    {
        try {
            return match ($action) {
                'login'              => $this->login($req),
                'logout'             => $this->logout(),
                'change_credentials' => $this->changeCredentials($req),
                'list_databases'     => ['ok' => true, 'databases' => DatabaseManager::list()],
                'create_database'    => $this->wrap(fn() => DatabaseManager::create($req['name'] ?? '')),
                'rename_database'    => $this->wrap(fn() => DatabaseManager::rename($req['old'] ?? '', $req['new'] ?? '')),
                'delete_database'    => $this->wrap(fn() => DatabaseManager::delete($req['name'] ?? '')),
                'list_tables'        => ['ok' => true, 'tables' => TableManager::listTables($req['db'] ?? '')],
                'create_table'       => $this->wrap(fn() => TableManager::create($req['db'], $req['name'], array_map('trim', explode(',', $req['columns'] ?? '')))),
                'rename_table'       => $this->wrap(fn() => TableManager::rename($req['db'], $req['old'], $req['new'])),
                'delete_table'       => $this->wrap(fn() => TableManager::delete($req['db'], $req['name'])),
                'get_page'           => $this->getPage($req),
                'insert_row'         => $this->insertRow($req),
                'update_row'         => $this->updateRow($req),
                'delete_rows'        => $this->deleteRows($req),
                'add_column'         => $this->wrap(fn() => $this->tm($req)->addColumn($req['name'])),
                'rename_column'      => $this->wrap(fn() => $this->tm($req)->renameColumn($req['old'], $req['new'])),
                'delete_column'      => $this->wrap(fn() => $this->tm($req)->deleteColumn($req['name'])),
                'clear_table'        => $this->wrap(fn() => $this->tm($req)->clear()),
                'set_row_color'      => $this->wrap(fn() => $this->tm($req)->setRowColor((int) $req['rid'], $req['color'])),
                'color_by_value'     => $this->colorByValue($req),
                'color_column'       => $this->wrap(fn() => $this->tm($req)->colorEntireColumn($req['col'], $req['color'])),
                'clear_colors'       => $this->wrap(fn() => $this->tm($req)->clearColors()),
                'apply_math'         => $this->applyMath($req),
                'generate_data'      => $this->generateData($req),
                'find_duplicates'    => $this->findDuplicates($req),
                'persist_sort'       => $this->persistSort($req),
                'export'             => $this->export($req),
                'import_upload'      => $this->importUpload($req),
                'import_columns'     => $this->importColumns($req),
                default              => ['ok' => false, 'msg' => 'إجراء غير معروف'],
            };
        } catch (Throwable $e) {
            return ['ok' => false, 'msg' => $e->getMessage()];
        }
    }

    private function wrap(callable $fn): array { $fn(); return ['ok' => true]; }
    private function tm(array $req): TableManager { return new TableManager($req['db'] ?? '', $req['table'] ?? ''); }

    private function login(array $req): array { return (new AuthManager())->login($req['user'] ?? '', $req['pass'] ?? ''); }
    private function logout(): array { (new AuthManager())->logout(); return ['ok' => true]; }

    private function changeCredentials(array $req): array
    {
        if (($req['pass'] ?? '') !== ($req['pass2'] ?? '')) return ['ok' => false, 'msg' => 'كلمتا المرور غير متطابقتين'];
        if (strlen($req['pass'] ?? '') < 4) return ['ok' => false, 'msg' => 'كلمة المرور قصيرة جداً'];
        if (trim($req['user'] ?? '') === '') return ['ok' => false, 'msg' => 'اسم المستخدم مطلوب'];
        (new AuthManager())->changeCredentials($req['user'], $req['pass']);
        return ['ok' => true];
    }

    private function getPage(array $req): array
    {
        $tm = $this->tm($req);
        $page = (int) ($req['page'] ?? 0);
        $size = (int) ($req['size'] ?? Config::DEFAULT_PAGE_SIZE);
        $search = (string) ($req['search'] ?? '');
        $sort = [];
        if (!empty($req['sort'])) { $decoded = json_decode((string) $req['sort'], true); if (is_array($decoded)) $sort = $decoded; }
        $data = $tm->getPage($page, $size, $search, $sort);
        $total = $tm->count($search);
        return [
            'ok' => true, 'columns' => $data['columns'], 'rows' => $data['rows'], 'total' => $total,
            'page' => $page, 'size' => $size, 'total_pages' => max(1, (int) ceil($total / max(1, $size))),
            'column_colors' => $tm->columnColors(),
        ];
    }

    private function insertRow(array $req): array
    {
        $tm = $this->tm($req);
        $data = json_decode((string) ($req['data'] ?? '{}'), true) ?: [];
        return ['ok' => true, 'rid' => $tm->insertRow($data)];
    }

    private function updateRow(array $req): array
    {
        $tm = $this->tm($req);
        $data = json_decode((string) ($req['data'] ?? '{}'), true) ?: [];
        $tm->updateRow((int) $req['rid'], $data);
        return ['ok' => true];
    }

    private function deleteRows(array $req): array
    {
        $tm = $this->tm($req);
        $rids = json_decode((string) ($req['rids'] ?? '[]'), true) ?: [];
        return ['ok' => true, 'deleted' => $tm->deleteRows(array_map('intval', $rids))];
    }

    private function colorByValue(array $req): array
    {
        $tm = $this->tm($req);
        return ['ok' => true, 'colored' => $tm->colorRowsMatching($req['col'], $req['value'], $req['color'])];
    }

    private function applyMath(array $req): array
    {
        $tm = $this->tm($req);
        return array_merge(['ok' => true], $tm->applyMath($req['col'], $req['formula'], $req['result_col'] ?: 'النتيجة_الحسابية'));
    }

    private function generateData(array $req): array
    {
        $tm = $this->tm($req);
        $res = $tm->generate((string) $req['pool'], max(1, (int) $req['length']), max(1, (int) $req['rows']),
            (string) $req['mode'], $req['target_col'] !== '' ? $req['target_col'] : null, $req['new_col_name'] ?? null);
        return array_merge(['ok' => true], $res);
    }

    private function findDuplicates(array $req): array
    {
        $tm = $this->tm($req);
        $cols = json_decode((string) $req['cols'], true) ?: [];
        return array_merge(['ok' => true], $tm->findDuplicates($cols, $req['mode']));
    }

    private function persistSort(array $req): array
    {
        $tm = $this->tm($req);
        $sort = json_decode((string) $req['sort'], true) ?: [];
        $tm->persistSort($sort);
        return ['ok' => true];
    }

    private function export(array $req): array
    {
        $tm = $this->tm($req);
        $data = $tm->getPage(0, 5_000_000, (string) ($req['search'] ?? ''));
        $cols = $data['columns'];
        $rows = array_map(fn($r) => array_map(fn($c) => $r[$c], $cols), $data['rows']);
        $fmt = $req['format'];
        $content = match ($fmt) {
            'csv'  => Exporter::csv($cols, $rows),
            'txt'  => Exporter::txt($cols, $rows),
            'sql'  => Exporter::sql($cols, $rows, $req['table'] ?? 'exported_data'),
            'html' => Exporter::html($cols, $rows),
            default => throw new RuntimeException('صيغة غير مدعومة'),
        };
        $tmpName = 'export_' . bin2hex(random_bytes(6)) . '.' . $fmt;
        $tmpPath = sys_get_temp_dir() . '/' . $tmpName;
        file_put_contents($tmpPath, $content);
        $_SESSION['zdb_export'][$tmpName] = $tmpPath;
        return ['ok' => true, 'download' => $tmpName];
    }

    private function importUpload(array $req): array
    {
        if (empty($_FILES['file'])) return ['ok' => false, 'msg' => 'لم يتم رفع ملف'];
        $tmp = sys_get_temp_dir() . '/import_' . bin2hex(random_bytes(6)) . '.csv';
        move_uploaded_file($_FILES['file']['tmp_name'], $tmp);
        $fh = fopen($tmp, 'r');
        $headers = fgetcsv($fh);
        fclose($fh);
        $_SESSION['zdb_import_file'] = $tmp;
        return ['ok' => true, 'headers' => $headers ?: []];
    }

    private function importColumns(array $req): array
    {
        $tm = $this->tm($req);
        $tmp = $_SESSION['zdb_import_file'] ?? '';
        $cols = json_decode((string) $req['src_cols'], true) ?: [];
        $names = json_decode((string) $req['new_names'], true) ?: [];
        return array_merge(['ok' => true], $tm->importColumns($tmp, $cols, $names, (string) $req['fill_mode']));
    }
}

// ==================================================================
//  DOWNLOAD HANDLER
// ==================================================================
if (isset($_GET['download'])) {
    $name = basename($_GET['download']);
    $path = $_SESSION['zdb_export'][$name] ?? null;
    if ($path && file_exists($path)) {
        $ext = pathinfo($path, PATHINFO_EXTENSION);
        $mimes = ['csv' => 'text/csv', 'txt' => 'text/plain', 'sql' => 'application/sql', 'html' => 'text/html'];
        header('Content-Type: ' . ($mimes[$ext] ?? 'application/octet-stream') . '; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $name . '"');
        readfile($path);
        exit;
    }
    http_response_code(404);
    exit('File not found');
}

// ==================================================================
//  API ROUTING
// ==================================================================
if (isset($_REQUEST['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    $action = (string) $_REQUEST['action'];
    $auth = new AuthManager();
    if ($action !== 'login' && !$auth->isLoggedIn()) {
        echo json_encode(['ok' => false, 'msg' => 'غير مصرح — الرجاء تسجيل الدخول'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    echo json_encode((new Api())->handle($action, $_REQUEST), JSON_UNESCAPED_UNICODE);
    exit;
}

// ==================================================================
//  PAGE RENDER
// ==================================================================
$auth = new AuthManager();
$loggedIn = $auth->isLoggedIn();
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title><?= Config::APP_NAME ?> — <?= Config::APP_VERSION ?></title>
<style>
:root{
  --bg:#0d1117; --sidebar:#161b22; --bar:#161b22; --tree:#1c2128;
  --fg:#e6edf3; --muted:#8b949e; --border:#30363d; --gold:#c9a84c;
  --accent:#00d4ff; --danger:#e74c3c; --sel:#0078d7;
}
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',Tahoma,Arial,sans-serif;background:var(--bg);color:var(--fg);height:100vh;overflow:hidden}
.hidden{display:none !important}
button{font-family:inherit;cursor:pointer;border:none}
input,select{font-family:inherit}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:var(--tree)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:5px}

/* ---------- Login ---------- */
#loginScreen{display:flex;align-items:center;justify-content:center;height:100vh;background:var(--bg);padding:16px}
.login-card{width:420px;max-width:100%;background:var(--sidebar);border:1px solid var(--border);border-radius:10px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.login-topbar{height:4px;background:var(--gold)}
.login-body{padding:30px 36px}
.login-logo{text-align:center;margin-bottom:18px}
.login-logo .brack{font-family:'Courier New',monospace;font-size:30px;color:var(--gold);font-weight:bold}
.login-logo h1{font-size:20px;margin:6px 0 2px}
.login-logo p{color:var(--muted);font-size:12px;margin:0}
.field{margin-bottom:14px}
.field label{display:block;font-size:12px;color:var(--muted);margin-bottom:5px}
.field input{width:100%;padding:11px 12px;background:var(--tree);border:1px solid var(--border);border-radius:6px;color:var(--fg);font-size:14px;outline:none}
.field input:focus{border-color:var(--accent)}
.err{color:var(--danger);font-size:12.5px;min-height:18px;text-align:center;margin:6px 0}
.btn-gold{width:100%;padding:12px;background:var(--gold);color:#000;font-weight:bold;border-radius:6px;font-size:15px}
.btn-gold:hover{background:#a07830}
.login-foot{text-align:center;color:#3d4450;font-size:11px;margin-top:16px}

/* ---------- App layout ---------- */
#app{display:flex;height:100vh;position:relative}
#sidebar{width:270px;background:var(--sidebar);display:flex;flex-direction:column;border-inline-end:1px solid var(--border);z-index:900}
.side-title{padding:12px;text-align:center;font-weight:bold;color:var(--gold);font-size:13px;letter-spacing:1px;display:flex;align-items:center;justify-content:center;gap:8px}
.side-search{padding:0 10px 8px}
.side-search input{width:100%;padding:6px 8px;background:var(--tree);border:1px solid var(--border);border-radius:5px;color:var(--fg);font-size:12px}
.side-tools{display:grid;grid-template-columns:1fr 1fr;gap:6px;padding:0 10px 8px}
.side-tools button{padding:7px;border-radius:5px;color:#fff;font-size:12px;font-weight:bold}
#navTree{flex:1;overflow:auto;padding:4px 8px}
.nav-db{padding:7px 8px;border-radius:5px;cursor:pointer;font-size:13px;font-weight:bold;color:var(--gold);display:flex;align-items:center;gap:6px}
.nav-db:hover{background:#1f242c}
.nav-tbl{padding:6px 10px 6px 24px;border-radius:5px;cursor:pointer;font-size:12.5px;color:var(--fg)}
.nav-tbl:hover{background:#1f242c}
.nav-tbl.active{background:var(--sel);color:#fff}
.side-bottom{padding:10px;border-top:1px solid var(--border)}
.side-bottom button{width:100%;padding:9px;margin-bottom:6px;border-radius:5px;color:#fff;font-size:12.5px}

#main{flex:1;display:flex;flex-direction:column;min-width:0}
#topbar{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
#toolBtns{display:flex;flex-wrap:wrap;gap:5px}
#toolBtns button{padding:7px 12px;border-radius:5px;color:#fff;font-size:12.5px;font-weight:bold;white-space:nowrap}
#topRight{display:flex;align-items:center;gap:6px}
#topRight input{padding:8px 10px;background:var(--tree);border:1px solid var(--border);border-radius:5px;color:var(--fg);width:220px;font-size:13px}
#sidebarToggle{display:none;width:38px;height:38px;background:var(--gold);color:#000;border-radius:6px;font-size:18px;font-weight:bold;align-items:center;justify-content:center}
#sidebarOverlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:800}
#sidebarOverlay.show{display:block}

#statusBar{padding:4px 16px;font-size:12.5px;color:var(--muted);font-style:italic;border-bottom:1px solid #1a1f27}
#tableWrap{flex:1;overflow:auto;margin:8px 14px;border:1px solid var(--border);border-radius:6px}
table.zdb{border-collapse:collapse;width:100%;font-size:13px}
table.zdb thead th{position:sticky;top:0;background:#000;color:var(--fg);padding:9px 10px;border:1px solid var(--border);font-weight:bold;cursor:pointer;user-select:none;white-space:nowrap}
table.zdb thead th:hover{background:#1a1a1a}
table.zdb td{padding:7px 10px;border:1px solid var(--border);text-align:center;background:var(--tree);white-space:nowrap}
table.zdb tbody tr:hover td{background:#232a33}
table.zdb tbody tr.selected td{background:var(--sel) !important;color:#fff}
.sort-arrow{font-size:10px;margin-inline-start:4px;color:var(--accent)}
.ctx-menu{position:fixed;background:var(--sidebar);border:1px solid var(--border);border-radius:7px;z-index:3000;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.55);min-width:200px}
.ctx-item{padding:10px 16px;font-size:13px;color:var(--fg);cursor:pointer;white-space:nowrap}
.ctx-item:hover{background:#232a33}
.ctx-item.danger:hover{background:#3a1414;color:#ff8080}

#rowTools{display:flex;gap:8px;padding:6px 14px}
#rowTools button{padding:7px 14px;border-radius:5px;color:#fff;font-size:12.5px;font-weight:bold}

#pageBar{display:flex;justify-content:space-between;align-items:center;padding:8px 14px;border-top:1px solid var(--border);flex-wrap:wrap;gap:8px}
#pageBar select, #pageBar button{padding:6px 10px;border-radius:5px;background:#2c3e50;color:#fff;font-size:12.5px}
#pageBar select{background:var(--tree);border:1px solid var(--border);color:var(--fg)}
#pageLbl{font-weight:bold;font-size:13px;padding:0 10px}

/* ---------- Modal ---------- */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:1000;padding:14px}
.modal{background:var(--sidebar);border:1px solid var(--border);border-radius:10px;width:480px;max-width:100%;max-height:88vh;overflow:auto;box-shadow:0 20px 60px rgba(0,0,0,.6)}
.modal.wide{width:640px}
.modal-top{height:3px;background:var(--gold)}
.modal-head{padding:16px 20px 4px;text-align:center}
.modal-head h2{margin:0;font-size:16px;color:var(--gold)}
.modal-body{padding:16px 24px}
.modal-body label{display:block;font-size:12px;font-weight:bold;color:var(--muted);margin:10px 0 4px}
.modal-body input[type=text],.modal-body input[type=number],.modal-body input[type=password],.modal-body input[type=file],.modal-body select{
  width:100%;padding:9px 10px;background:var(--tree);border:1px solid var(--border);border-radius:6px;color:var(--fg);font-size:13px;outline:none}
.modal-body input:focus,.modal-body select:focus{border-color:var(--accent)}
.modal-foot{display:flex;gap:10px;padding:16px 24px;border-top:1px solid var(--border);flex-wrap:wrap}
.modal-foot button{flex:1 1 120px;padding:11px;border-radius:6px;color:#fff;font-weight:bold;font-size:13.5px}
.checklist{max-height:180px;overflow:auto;background:var(--tree);border:1px solid var(--border);border-radius:6px;padding:8px}
.checklist label{display:flex;gap:6px;align-items:center;font-weight:normal;color:var(--fg);font-size:12.5px;padding:3px 0}
.color-swatches{display:grid;grid-template-columns:repeat(8,1fr);gap:6px;margin:6px 0}
.color-swatches div{width:100%;aspect-ratio:1;border-radius:4px;border:2px solid #fff2;cursor:pointer}
.sort-row{display:flex;gap:6px;margin-bottom:6px;align-items:center;flex-wrap:wrap}
.sort-row select{flex:1;min-width:100px}
.mini-btn{background:#30363d;color:#fff;padding:6px 12px;border-radius:5px;font-size:11.5px}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#1c2128;border:1px solid var(--border);
  padding:12px 20px;border-radius:8px;color:var(--fg);font-size:13px;z-index:4000;box-shadow:0 8px 30px rgba(0,0,0,.5);max-width:90vw}
.toast.ok{border-color:#27ae60}
.toast.err{border-color:var(--danger)}

/* ---------- Mobile responsive ---------- */
@media (max-width: 860px){
  #sidebarToggle{display:inline-flex}
  #sidebar{position:fixed;top:0;bottom:0;right:0;width:82%;max-width:300px;transform:translateX(100%);transition:transform .25s ease}
  html[dir="rtl"] #sidebar{transform:translateX(100%)}
  #sidebar.open{transform:translateX(0)}
  #toolBtns{flex-wrap:nowrap;overflow-x:auto;-webkit-overflow-scrolling:touch;padding-bottom:6px;max-width:100%}
  #toolBtns button{flex:0 0 auto}
  #topRight input{width:130px}
  table.zdb{font-size:11.5px}
  .modal{width:100%}
  .modal-foot button{flex:1 1 45%}
  #pageBar{flex-direction:column;align-items:stretch;text-align:center}
}
</style>
</head>
<body>

<!-- ===================== LOGIN SCREEN ===================== -->
<div id="loginScreen" class="<?= $loggedIn ? 'hidden' : '' ?>">
  <div class="login-card">
    <div class="login-topbar"></div>
    <div class="login-body">
      <div class="login-logo">
        <div class="brack">[DB]</div>
        <h1>ZAEEM DB ULTRA</h1>
        <p><?= Config::APP_VERSION ?> — Encrypted Vault Access</p>
      </div>
      <div class="field"><label>Username</label><input id="loginUser" type="text" value="root"></div>
      <div class="field"><label>Password</label><input id="loginPass" type="password"></div>
      <div class="err" id="loginErr"></div>
      <button class="btn-gold" onclick="ZDB.login()">Login &gt;</button>
      <div class="login-foot">Encrypted Vault (libsodium) — SQLite Powered Engine</div>
    </div>
  </div>
</div>

<!-- ===================== MAIN APP ===================== -->
<div id="app" class="<?= $loggedIn ? '' : 'hidden' ?>">
  <div id="sidebarOverlay" onclick="ZDB.toggleSidebar()"></div>
  <div id="sidebar">
    <div class="side-title">DATABASE EXPLORER</div>
    <div class="side-search"><input id="navSearch" placeholder="بحث..." oninput="ZDB.refreshNav()"></div>
    <div class="side-tools">
      <button style="background:#27ae60" onclick="ZDB.modalNewDb()">+ DB</button>
      <button style="background:#2980b9" onclick="ZDB.modalNewTable()">+ Table</button>
      <button style="background:#f1c40f;color:#000" onclick="ZDB.renameSelected()">Rename</button>
      <button style="background:#e74c3c" onclick="ZDB.deleteSelected()">Delete</button>
    </div>
    <div id="navTree"></div>
    <div class="side-bottom">
      <button style="background:#34495e" onclick="ZDB.toggleTheme()">Theme Toggle</button>
      <button style="background:#2980b9" onclick="ZDB.modalAccount()">Account Settings</button>
      <button style="background:#c0392b" onclick="ZDB.logout()">Exit</button>
    </div>
  </div>

  <div id="main">
    <div id="topbar">
      <div style="display:flex;align-items:center;gap:8px">
        <button id="sidebarToggle" onclick="ZDB.toggleSidebar()">☰</button>
        <div id="toolBtns">
          <button style="background:#2e44ad" onclick="ZDB.modalExport()">export*</button>
          <button style="background:#8e44ad" onclick="ZDB.modalInsertRow()">+ Row</button>
          <button style="background:#34495e" onclick="ZDB.modalAddColumn()">+ Column</button>
          <button style="background:#d35400" onclick="ZDB.clearTable()">Clear Table</button>
          <button style="background:#f39c12" onclick="ZDB.modalSort()">Sort</button>
          <button style="background:#1abc9c" onclick="ZDB.modalColors()">Row Colors</button>
          <button style="background:#2980b9" onclick="ZDB.editSelectedRow()">Edit Row</button>
          <button style="background:#c0392b" onclick="ZDB.deleteSelectedRows()">Delete Row</button>
          <button style="background:#16a085" onclick="ZDB.modalImport()">Import Column</button>
          <button style="background:#6c3483" onclick="ZDB.modalFunctions()">Functions</button>
          <button style="background:#1a5276" onclick="ZDB.modalGenerate()">Generate Data</button>
          <button style="background:#78281f" onclick="ZDB.modalDuplicates()">Find Duplicates</button>
        </div>
      </div>
      <div id="topRight">
        <span style="font-size:13px">Search:</span>
        <input id="dataSearch" placeholder="بحث فى البيانات..." oninput="ZDB.debounceSearch()">
      </div>
    </div>
    <div id="statusBar">No table selected</div>
    <div id="tableWrap">
      <table class="zdb"><thead id="theadRow"></thead><tbody id="tbodyRows"></tbody></table>
    </div>
    <div id="rowTools">
      <button style="background:#27ae60" onclick="ZDB.editSelectedRow()">Edit Row</button>
      <button style="background:#c0392b" onclick="ZDB.deleteSelectedRows()">Delete Row</button>
    </div>
    <div id="pageBar">
      <div>
        <button onclick="ZDB.goPage(0)">&laquo;</button>
        <button onclick="ZDB.prevPage()">&lsaquo;</button>
        <span id="pageLbl">Page 1 / 1 | 0 rows</span>
        <button onclick="ZDB.nextPage()">&rsaquo;</button>
        <button onclick="ZDB.goLast()">&raquo;</button>
      </div>
      <div>
        Size:
        <select id="pageSize" onchange="ZDB.state.page=0;ZDB.loadPage()">
          <?php foreach (Config::PAGE_SIZES as $ps): ?>
          <option value="<?= $ps ?>" <?= $ps === Config::DEFAULT_PAGE_SIZE ? 'selected' : '' ?>><?= $ps ?></option>
          <?php endforeach; ?>
        </select>
        Page:
        <select id="pageJump" onchange="ZDB.goPage(parseInt(this.value)-1)"><option>1</option></select>
      </div>
    </div>
  </div>
</div>

<div id="modalRoot"></div>
<div id="toastRoot"></div>

<script>
const ZDB = (() => {
  const state = {
    db: null, table: null, columns: [], rows: [],
    page: 0, totalPages: 1, total: 0, selected: new Set(),
    sort: [], searchTimer: null, columnColors: {}, dark: true,
    selNav: null, bulkMode: false, _modalKeyHandler: null
  };

  const api = async (action, params = {}) => {
    const body = new URLSearchParams({ action, ...params });
    const res = await fetch('', { method: 'POST', body });
    return res.json();
  };

  const toast = (msg, ok = true) => {
    const el = document.createElement('div');
    el.className = 'toast ' + (ok ? 'ok' : 'err');
    el.textContent = msg;
    document.getElementById('toastRoot').appendChild(el);
    setTimeout(() => el.remove(), 3200);
  };

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  // ---------------- LOGIN ----------------
  async function login() {
    const user = document.getElementById('loginUser').value.trim();
    const pass = document.getElementById('loginPass').value;
    const r = await api('login', { user, pass });
    if (r.ok) location.reload();
    else document.getElementById('loginErr').textContent = r.msg || 'خطأ';
  }
  async function logout() { await api('logout'); location.reload(); }

  // ---------------- MOBILE SIDEBAR ----------------
  function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('sidebarOverlay').classList.toggle('show');
  }
  function closeSidebarIfMobile() {
    if (window.innerWidth <= 860) {
      document.getElementById('sidebar').classList.remove('open');
      document.getElementById('sidebarOverlay').classList.remove('show');
    }
  }

  // ---------------- NAV ----------------
  async function refreshNav() {
    const q = document.getElementById('navSearch').value.toLowerCase().trim();
    const dbr = await api('list_databases');
    const tree = document.getElementById('navTree');
    tree.innerHTML = '';
    for (const db of (dbr.databases || [])) {
      const tr = await api('list_tables', { db });
      const tables = (tr.tables || []);
      let show = tables;
      const dbMatches = db.toLowerCase().includes(q);
      if (q && !dbMatches) show = tables.filter(t => t.toLowerCase().includes(q));
      if (q && !dbMatches && show.length === 0) continue;

      const dbEl = document.createElement('div');
      dbEl.className = 'nav-db';
      dbEl.textContent = '📁 ' + db;
      dbEl.onclick = () => { state.db = db; state.table = null; state.selNav = {type:'db', name: db};
        document.getElementById('statusBar').textContent = 'Database: ' + db; };
      tree.appendChild(dbEl);

      for (const t of show) {
        const tEl = document.createElement('div');
        tEl.className = 'nav-tbl' + (state.db===db && state.table===t ? ' active' : '');
        tEl.textContent = '📄 ' + t;
        tEl.onclick = () => {
          state.db = db; state.table = t; state.selNav = {type:'tbl', name: t, db};
          state.page = 0; state.sort = []; state.bulkMode = false;
          document.querySelectorAll('.nav-tbl').forEach(e=>e.classList.remove('active'));
          tEl.classList.add('active');
          loadPage();
          closeSidebarIfMobile();
        };
        tree.appendChild(tEl);
      }
    }
  }

  function modalNewDb() {
    openModal('قاعدة بيانات جديدة', `<label>اسم القاعدة</label><input type="text" id="mNewDbName">`,
      [{label:'إنشاء', bg:'#27ae60', action: async () => {
        const name = document.getElementById('mNewDbName').value.trim();
        if (!name) return;
        const r = await api('create_database', { name });
        if (r.ok) { closeModal(); refreshNav(); toast('تم الإنشاء'); } else toast(r.msg, false);
      }}]);
  }

  function modalNewTable() {
    if (!state.db) return toast('اختر قاعدة بيانات أولاً', false);
    openModal('جدول جديد', `
      <label>اسم الجدول</label><input type="text" id="mNewTblName">
      <label>الأعمدة (مفصولة بفاصلة)</label><input type="text" id="mNewTblCols" placeholder="id, name, age">
    `, [{label:'إنشاء', bg:'#2980b9', action: async () => {
      const name = document.getElementById('mNewTblName').value.trim();
      const columns = document.getElementById('mNewTblCols').value.trim();
      if (!name || !columns) return;
      const r = await api('create_table', { db: state.db, name, columns });
      if (r.ok) { closeModal(); refreshNav(); toast('تم الإنشاء'); } else toast(r.msg, false);
    }}]);
  }

  async function renameSelected() {
    if (!state.selNav) return;
    const newName = prompt('الاسم الجديد:');
    if (!newName) return;
    const r = state.selNav.type === 'db'
      ? await api('rename_database', { old: state.selNav.name, new: newName })
      : await api('rename_table', { db: state.selNav.db, old: state.selNav.name, new: newName });
    if (r.ok) { refreshNav(); toast('تم التعديل'); } else toast(r.msg, false);
  }

  async function deleteSelected() {
    if (!state.selNav) return;
    if (!confirm(`حذف '${state.selNav.name}' نهائياً؟`)) return;
    const r = state.selNav.type === 'db'
      ? await api('delete_database', { name: state.selNav.name })
      : await api('delete_table', { db: state.selNav.db, name: state.selNav.name });
    if (r.ok) {
      if (state.selNav.type === 'tbl') { state.table = null; renderEmpty(); }
      state.selNav = null; refreshNav(); toast('تم الحذف');
    } else toast(r.msg, false);
  }

  function renderEmpty() {
    document.getElementById('theadRow').innerHTML = '';
    document.getElementById('tbodyRows').innerHTML = '';
    document.getElementById('statusBar').textContent = 'No table selected';
    document.getElementById('pageLbl').textContent = 'Page 1 / 1 | 0 rows';
  }

  // ---------------- TABLE / PAGE LOADING ----------------
  async function loadPage() {
    if (!state.db || !state.table) return;
    const size = document.getElementById('pageSize').value;
    const search = document.getElementById('dataSearch').value;
    const r = await api('get_page', { db: state.db, table: state.table, page: state.page, size, search, sort: JSON.stringify(state.sort) });
    if (!r.ok) return toast(r.msg, false);
    state.columns = r.columns; state.rows = r.rows;
    state.total = r.total; state.totalPages = r.total_pages;
    state.columnColors = r.column_colors || {};
    state.selected.clear(); state.bulkMode = false;
    renderTable();
    document.getElementById('statusBar').textContent = `${state.db}  >>  ${state.table}     |     Total rows: ${r.total.toLocaleString()}`;
    updatePageBar(r);
  }

  function updatePageBar(r) {
    const start = r.page * r.size + 1;
    const end = Math.min(r.page * r.size + r.size, r.total);
    document.getElementById('pageLbl').textContent =
      `Page ${r.page+1} / ${r.total_pages}   |   ${r.total ? start.toLocaleString() : 0} - ${end.toLocaleString()}   |   Total: ${r.total.toLocaleString()}`;
    const sel = document.getElementById('pageJump');
    sel.innerHTML = '';
    for (let i=1;i<=r.total_pages;i++){
      const o = document.createElement('option'); o.value=i; o.textContent=i;
      if (i-1===r.page) o.selected = true;
      sel.appendChild(o);
    }
  }

  function renderTable() {
    const thead = document.getElementById('theadRow');
    const tbody = document.getElementById('tbodyRows');
    thead.innerHTML = '<tr>' + state.columns.map(c => {
      const s = state.sort.find(x => x.col === c);
      const arrow = s ? `<span class="sort-arrow">${s.dir==='ASC'?'▲':'▼'}</span>` : '';
      const bg = state.columnColors[c] ? `style="color:${state.columnColors[c]}"` : '';
      const cSafe = c.replace(/'/g,"\\'");
      return `<th ${bg} onclick="ZDB.headerClick('${cSafe}')" oncontextmenu="return ZDB.headerContext(event,'${cSafe}')">${esc(c)}${arrow}</th>`;
    }).join('') + '</tr>';

    tbody.innerHTML = state.rows.map(r => {
      const rid = r.__rid__;
      const tds = state.columns.map(c => {
        const style = r.__color__ ? `style="color:${r.__color__}"` : (state.columnColors[c] ? `style="color:${state.columnColors[c]}"` : '');
        return `<td ${style}>${esc(r[c])}</td>`;
      }).join('');
      return `<tr data-rid="${rid}" onclick="ZDB.rowClick(event,${rid})" oncontextmenu="return ZDB.rowContext(event,${rid})">${tds}</tr>`;
    }).join('');
  }

  // ---------------- COLUMN CONTEXT MENU (Rename / Delete) ----------------
  function closeCtxMenus() { document.querySelectorAll('.ctx-menu').forEach(m => m.remove()); }

  function openCtxMenu(ev, itemsHtml, handlers) {
    closeCtxMenus();
    const menu = document.createElement('div');
    menu.className = 'ctx-menu';
    const x = Math.min(ev.clientX, window.innerWidth - 220);
    const y = Math.min(ev.clientY, window.innerHeight - 120);
    menu.style.left = x + 'px'; menu.style.top = y + 'px';
    menu.innerHTML = itemsHtml;
    document.body.appendChild(menu);
    const remove = () => { menu.remove(); document.removeEventListener('click', remove); };
    setTimeout(() => document.addEventListener('click', remove), 0);
    Object.keys(handlers).forEach(act => {
      const el = menu.querySelector(`[data-act="${act}"]`);
      if (el) el.onclick = () => { remove(); handlers[act](); };
    });
  }

  function headerContext(ev, col) {
    ev.preventDefault();
    openCtxMenu(ev, `
      <div class="ctx-item" data-act="rename">✏️ إعادة تسمية العمود</div>
      <div class="ctx-item danger" data-act="delete">🗑 حذف العمود</div>`, {
      rename: async () => {
        const newName = prompt(`الاسم الجديد للعمود '${col}':`, col);
        if (!newName || newName.trim() === '' || newName === col) return;
        const r = await api('rename_column', { db: state.db, table: state.table, old: col, new: newName.trim() });
        if (r.ok) { loadPage(); toast('تم تعديل اسم العمود'); } else toast(r.msg, false);
      },
      delete: async () => {
        if (!confirm(`حذف العمود '${col}' وكل بياناته نهائياً؟`)) return;
        const r = await api('delete_column', { db: state.db, table: state.table, name: col });
        if (r.ok) { loadPage(); toast('تم حذف العمود'); } else toast(r.msg, false);
      }
    });
    return false;
  }

  // ---------------- ROW SELECTION: right-click = select by count, left-click on bulk = confirm/cancel ----------------
  function rowContext(ev, rid) {
    ev.preventDefault();
    openCtxMenu(ev, `<div class="ctx-item" data-act="count">🔢 تحديد عدد صفوف من هنا</div>`, {
      count: () => {
        const n = parseInt(prompt('عدد الصفوف المراد تحديدها بدءاً من هذا الصف:', '5'), 10);
        if (!n || n < 1) return;
        const startIdx = state.rows.findIndex(r => r.__rid__ === rid);
        if (startIdx === -1) return;
        state.selected.clear();
        document.querySelectorAll('#tbodyRows tr.selected').forEach(e=>e.classList.remove('selected'));
        state.rows.slice(startIdx, startIdx + n).forEach(r => state.selected.add(r.__rid__));
        document.querySelectorAll('#tbodyRows tr').forEach(tr => {
          if (state.selected.has(parseInt(tr.dataset.rid, 10))) tr.classList.add('selected');
        });
        state.bulkMode = true;
        toast(`تم تحديد ${state.selected.size} صف — اضغط كليك شمال على أي صف محدد للمتابعة`);
      }
    });
    return false;
  }

  function rowClick(ev, rid) {
    if (state.bulkMode) {
      openCtxMenu(ev, `
        <div class="ctx-item" data-act="cancel">↩️ إلغاء التحديد</div>
        <div class="ctx-item danger" data-act="delete">🗑 حذف الصفوف المحددة (${state.selected.size})</div>`, {
        cancel: () => {
          state.selected.clear(); state.bulkMode = false;
          document.querySelectorAll('#tbodyRows tr.selected').forEach(e=>e.classList.remove('selected'));
        },
        delete: async () => { await deleteSelectedRows(); state.bulkMode = false; }
      });
      return;
    }
    const tr = ev.currentTarget;
    if (state.selected.has(rid)) { state.selected.delete(rid); tr.classList.remove('selected'); }
    else { state.selected.add(rid); tr.classList.add('selected'); }
  }

  function headerClick(col) {
    const existing = state.sort.find(s => s.col === col);
    if (existing) existing.dir = existing.dir === 'ASC' ? 'DESC' : 'ASC';
    else state.sort = [{ col, dir: 'ASC', numeric: false }];
    state.page = 0;
    loadPage();
  }

  function debounceSearch() {
    clearTimeout(state.searchTimer);
    state.searchTimer = setTimeout(() => { state.page = 0; loadPage(); }, 350);
  }

  function goPage(p) { state.page = Math.max(0, Math.min(p, state.totalPages-1)); loadPage(); }
  function nextPage() { if (state.page < state.totalPages-1) { state.page++; loadPage(); } }
  function prevPage() { if (state.page > 0) { state.page--; loadPage(); } }
  function goLast() { state.page = state.totalPages-1; loadPage(); }

  // ---------------- CRUD ----------------
  function modalInsertRow() {
    if (!state.table) return toast('اختر جدول أولاً', false);
    const fields = state.columns.map(c => `<label>${esc(c)}</label><input type="text" data-col="${esc(c)}">`).join('');
    openModal('إضافة صف جديد', fields, [{label:'حفظ', bg:'#8e44ad', action: async () => {
      const data = {};
      document.querySelectorAll('#modalRoot [data-col]').forEach(i => data[i.dataset.col] = i.value);
      const r = await api('insert_row', { db: state.db, table: state.table, data: JSON.stringify(data) });
      if (r.ok) { closeModal(); loadPage(); toast('تمت الإضافة'); } else toast(r.msg, false);
    }}]);
  }

  function editSelectedRow() {
    if (state.selected.size !== 1) return toast('اختر صفاً واحداً بالضبط للتعديل', false);
    const rid = [...state.selected][0];
    const row = state.rows.find(r => r.__rid__ === rid);
    if (!row) return;
    const fields = state.columns.map(c => `<label>${esc(c)}</label><input type="text" data-col="${esc(c)}" value="${esc(row[c])}">`).join('');
    openModal('تعديل الصف', fields, [{label:'حفظ', bg:'#27ae60', action: async () => {
      const data = {};
      document.querySelectorAll('#modalRoot [data-col]').forEach(i => data[i.dataset.col] = i.value);
      const r = await api('update_row', { db: state.db, table: state.table, rid, data: JSON.stringify(data) });
      if (r.ok) { closeModal(); loadPage(); toast('تم الحفظ'); } else toast(r.msg, false);
    }}]);
  }

  async function deleteSelectedRows() {
    if (state.selected.size === 0) return toast('لم يتم تحديد أي صف', false);
    if (!confirm(`حذف ${state.selected.size} صف؟`)) return;
    const r = await api('delete_rows', { db: state.db, table: state.table, rids: JSON.stringify([...state.selected]) });
    if (r.ok) { loadPage(); toast(`تم حذف ${r.deleted} صف`); } else toast(r.msg, false);
  }

  function modalAddColumn() {
    if (!state.table) return toast('اختر جدول أولاً', false);
    openModal('عمود جديد', `<label>اسم العمود</label><input type="text" id="mColName">`,
      [{label:'إضافة', bg:'#34495e', action: async () => {
        const name = document.getElementById('mColName').value.trim();
        if (!name) return;
        const r = await api('add_column', { db: state.db, table: state.table, name });
        if (r.ok) { closeModal(); loadPage(); toast('تمت الإضافة'); } else toast(r.msg, false);
      }}]);
  }

  async function clearTable() {
    if (!state.table) return toast('اختر جدول أولاً', false);
    if (!confirm('مسح كل بيانات الجدول؟')) return;
    const r = await api('clear_table', { db: state.db, table: state.table });
    if (r.ok) { loadPage(); toast('تم المسح'); } else toast(r.msg, false);
  }

  // ---------------- SORT ----------------
  function modalSort() {
    if (!state.table) return toast('اختر جدول أولاً', false);
    const rowsHtml = state.columns.map((c,i) => `
      <div class="sort-row">
        <select data-scol>
          <option value="">(تجاهل)</option>
          ${state.columns.map(cc=>`<option value="${esc(cc)}" ${cc===c && i<1?'selected':''}>${esc(cc)}</option>`).join('')}
        </select>
        <select data-stype><option value="text">مدمج</option><option value="numeric">أرقام فقط</option></select>
        <select data-sdir><option value="ASC">تصاعدي</option><option value="DESC">تنازلي</option></select>
      </div>`).join('');
    openModal('الترتيب المتقدم', `<div id="sortRows">${rowsHtml}</div>`, [
      {label:'معاينة', bg:'#2980b9', action: () => doSort(false)},
      {label:'ترتيب وحفظ فوري', bg:'#27ae60', action: () => doSort(true)},
    ], true);
  }

  async function doSort(persist) {
    const rows = [...document.querySelectorAll('#sortRows .sort-row')];
    const sort = [];
    rows.forEach(r => {
      const col = r.querySelector('[data-scol]').value;
      if (!col) return;
      sort.push({ col, dir: r.querySelector('[data-sdir]').value, numeric: r.querySelector('[data-stype]').value === 'numeric' });
    });
    if (!sort.length) return toast('اختر عموداً واحداً على الأقل', false);
    state.sort = sort; state.page = 0;
    closeModal();
    await loadPage();
    if (persist) {
      const r = await api('persist_sort', { db: state.db, table: state.table, sort: JSON.stringify(sort) });
      toast(r.ok ? 'تم الترتيب والحفظ' : r.msg, r.ok);
      loadPage();
    } else toast('معاينة الترتيب مطبّقة');
  }

  // ---------------- ROW / COLUMN COLORS ----------------
  const PALETTE = ['#000000','#FF0000','#00FF00','#0000FF','#FFFF00','#FF00FF','#00FFFF','#800000',
                    '#008000','#000080','#808000','#800080','#008080','#808080','#C0C0C0','#FFFFFF'];
  function modalColors() {
    if (!state.table) return toast('اختر جدول أولاً', false);
    const swHtml = PALETTE.map(c=>`<div style="background:${c}" onclick="ZDB._pickColor('${c}')"></div>`).join('');
    openModal('ألوان الصفوف والأعمدة', `
      <label>العمود (اتركه فارغاً لتلوين الصفوف المحددة بالماوس)</label>
      <select id="mColorCol"><option value="">-- بدون --</option>${state.columns.map(c=>`<option value="${esc(c)}">${esc(c)}</option>`).join('')}</select>
      <label>كلمة دلالية (اختياري — تلوين الصفوف المطابقة فقط)</label>
      <input type="text" id="mColorVal">
      <label>اللون</label>
      <div class="color-swatches">${swHtml}</div>
      <input type="text" id="mColorHex" value="#00d4ff">
    `, [
      {label:'تطبيق', bg:'#27ae60', action: async () => {
        const col = document.getElementById('mColorCol').value;
        const val = document.getElementById('mColorVal').value.trim();
        const color = document.getElementById('mColorHex').value;
        if (col && !val) {
          const r = await api('color_column', { db: state.db, table: state.table, col, color });
          if (r.ok) { closeModal(); loadPage(); toast('تم تلوين العمود'); } else toast(r.msg,false);
        } else if (col && val) {
          const r = await api('color_by_value', { db: state.db, table: state.table, col, value: val, color });
          if (r.ok) { closeModal(); loadPage(); toast(`تم تلوين ${r.colored} صف`); } else toast(r.msg,false);
        } else {
          if (state.selected.size === 0) return toast('حدد صفوفاً أولاً أو اختر عموداً', false);
          for (const rid of state.selected) await api('set_row_color', { db: state.db, table: state.table, rid, color });
          closeModal(); loadPage(); toast('تم تلوين الصفوف المحددة');
        }
      }},
      {label:'مسح كل الألوان', bg:'#c0392b', action: async () => {
        const r = await api('clear_colors', { db: state.db, table: state.table });
        if (r.ok) { closeModal(); loadPage(); toast('تم المسح'); }
      }}
    ]);
  }
  function _pickColor(c) { document.getElementById('mColorHex').value = c; }

  // ---------------- MATH FUNCTIONS ----------------
  const FUNCTIONS = [
    ['x + 8','x + 8'], ['x**2 (تربيع)','x**2'], ['x**3 (تكعيب)','x**3'], ['abs(x)','abs(x)'],
    ['1/x','1/x'], ['sin(x)','sin(x)'], ['cos(x)','cos(x)'], ['tan(x)','tan(x)'],
    ['log(x)','log(x)'], ['log10(x)','log10(x)'], ['exp(x)','exp(x)'], ['sqrt(x)','sqrt(x)']
  ];
  function modalFunctions() {
    if (!state.table) return toast('اختر جدول أولاً', false);
    openModal('الدوال الرياضية', `
      <label>العمود الرقمي</label>
      <select id="mFnCol">${state.columns.map(c=>`<option value="${esc(c)}">${esc(c)}</option>`).join('')}</select>
      <label>دالة جاهزة</label>
      <select id="mFnPreset" onchange="document.getElementById('mFnFormula').value=this.value">
        ${FUNCTIONS.map(([label,val])=>`<option value="${val}">${label}</option>`).join('')}
      </select>
      <label>المعادلة (استخدم x)</label>
      <input type="text" id="mFnFormula" value="x + 8">
      <label>اسم عمود النتيجة</label>
      <input type="text" id="mFnResult" value="النتيجة_الحسابية">
    `, [{label:'تطبيق', bg:'#6c3483', action: async () => {
      const col = document.getElementById('mFnCol').value;
      const formula = document.getElementById('mFnFormula').value.trim();
      const result_col = document.getElementById('mFnResult').value.trim() || 'النتيجة_الحسابية';
      const r = await api('apply_math', { db: state.db, table: state.table, col, formula, result_col });
      if (r.ok) { closeModal(); loadPage(); toast(`تم التطبيق (${r.applied} صف، ${r.errors} خطأ)`); } else toast(r.msg, false);
    }}]);
  }

  // ---------------- GENERATE DATA ----------------
  function modalGenerate() {
    if (!state.table) return toast('اختر جدول أولاً', false);
    openModal('توليد بيانات عشوائية فريدة', `
      <label>نوع الرموز</label>
      <select id="mGenType">
        <option value="custom">رموز مخصصة (اكتبها بالأسفل)</option>
        <option value="letters">أحرف فقط A-Z a-z</option>
        <option value="digits">أرقام فقط</option>
        <option value="alnum">أحرف + أرقام</option>
        <option value="all">شامل (أحرف+أرقام+رموز)</option>
      </select>
      <label>رموز مخصصة</label>
      <input type="text" id="mGenPool" value="ABCDEFGHijklmnop0123456789!@#$">
      <label>طول الكود</label><input type="number" id="mGenLen" value="16" min="1">
      <label>عدد الصفوف</label><input type="number" id="mGenRows" value="20" min="1">
      <label>طريقة الإدراج</label>
      <select id="mGenMode">
        <option value="new_column">إضافة كعمود جديد</option>
        <option value="fill_existing">تعبئة عمود حالي</option>
        <option value="new_rows">إضافة كصفوف جديدة</option>
      </select>
      <label>العمود الهدف (لو تعبئة عمود حالي)</label>
      <select id="mGenTargetCol"><option value="">-- بدون --</option>${state.columns.map(c=>`<option value="${esc(c)}">${esc(c)}</option>`).join('')}</select>
      <label>اسم العمود الجديد</label><input type="text" id="mGenNewCol" value="generated_id">
    `, [{label:'توليد', bg:'#1a5276', action: async () => {
      const type = document.getElementById('mGenType').value;
      const pools = { letters:'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                      digits:'0123456789', alnum:'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
                      all:'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+' };
      const pool = type === 'custom' ? document.getElementById('mGenPool').value : pools[type];
      const length = document.getElementById('mGenLen').value;
      const rows = document.getElementById('mGenRows').value;
      const mode = document.getElementById('mGenMode').value;
      const target_col = document.getElementById('mGenTargetCol').value;
      const new_col_name = document.getElementById('mGenNewCol').value.trim();
      const r = await api('generate_data', { db: state.db, table: state.table, pool, length, rows, mode, target_col, new_col_name });
      if (r.ok) { closeModal(); loadPage(); toast(`تم توليد ${r.generated} من أصل ${r.requested}`); } else toast(r.msg, false);
    }}]);
  }

  // ---------------- DUPLICATES ----------------
  function modalDuplicates() {
    if (!state.table) return toast('اختر جدول أولاً', false);
    const checks = state.columns.map(c=>`<label><input type="checkbox" data-dupcol value="${esc(c)}" checked>${esc(c)}</label>`).join('');
    openModal('البحث عن التكرارات', `
      <label>الأعمدة</label>
      <div class="checklist">${checks}</div>
      <label>الإجراء</label>
      <select id="mDupMode">
        <option value="duplicates">عرض التكرارات فقط</option>
        <option value="unique">عرض القيم الفريدة فقط</option>
        <option value="count">حساب عدد التكرارات</option>
        <option value="delete">حذف الصفوف المكررة (إبقاء الأول)</option>
      </select>
      <div id="dupResultWrap" style="margin-top:10px;max-height:260px;overflow:auto"></div>
    `, [{label:'ابدأ البحث', bg:'#78281f', keepOpen:true, action: async () => {
      const cols = [...document.querySelectorAll('[data-dupcol]:checked')].map(i=>i.value);
      if (!cols.length) return toast('اختر عموداً واحداً على الأقل', false);
      const mode = document.getElementById('mDupMode').value;
      const r = await api('find_duplicates', { db: state.db, table: state.table, cols: JSON.stringify(cols), mode });
      if (!r.ok) return toast(r.msg, false);
      if (mode === 'delete') { closeModal(); loadPage(); toast(`تم حذف ${r.removed} صف مكرر`); return; }
      const wrap = document.getElementById('dupResultWrap');
      const cc = r.columns;
      wrap.innerHTML = `<div style="margin-bottom:6px;font-size:12px;color:var(--muted)">النتائج: ${r.rows.length}</div>
        <table class="zdb" style="font-size:11.5px"><thead><tr>${cc.map(c=>`<th>${esc(c)}</th>`).join('')}</tr></thead>
        <tbody>${r.rows.map(row=>`<tr>${cc.map(c=>`<td>${esc(row[c])}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
    }}], true);
  }

  // ---------------- IMPORT COLUMN (اختر أعمدة محددة أو الكل) ----------------
  function modalImport() {
    if (!state.table) return toast('اختر جدول أولاً', false);
    openModal('استيراد أعمدة من ملف آخر', `
      <label>اختر ملف CSV</label>
      <input type="file" id="mImpFile" accept=".csv">
      <div id="mImpColsWrap"></div>
      <label>الأسماء الجديدة (مفصولة بفاصلة، اختياري)</label>
      <input type="text" id="mImpNewNames">
      <label>عند اختلاف عدد الصفوف</label>
      <select id="mImpFillMode"><option value="pad">تعبئة فارغة</option><option value="truncate">قص لأقصر طول</option></select>
    `, [{label:'استيراد', bg:'#16a085', keepOpen:true, action: async () => {
      const cols = [...document.querySelectorAll('[data-impcol]:checked')].map(i=>i.value);
      if (!cols.length) return toast('اختر عموداً واحداً على الأقل', false);
      const names = document.getElementById('mImpNewNames').value.split(',').map(s=>s.trim());
      const fill_mode = document.getElementById('mImpFillMode').value;
      const r = await api('import_columns', { db: state.db, table: state.table, src_cols: JSON.stringify(cols), new_names: JSON.stringify(names), fill_mode });
      if (r.ok) { closeModal(); loadPage(); toast(`تم استيراد ${r.imported_rows} صف`); } else toast(r.msg, false);
    }}], true);

    document.getElementById('mImpFile').addEventListener('change', async (e) => {
      if (!e.target.files.length) return;
      const fd = new FormData(); fd.append('action', 'import_upload'); fd.append('file', e.target.files[0]);
      const res = await fetch('', { method:'POST', body: fd });
      const r = await res.json();
      if (!r.ok) return toast(r.msg, false);
      document.getElementById('mImpColsWrap').innerHTML = `
        <label>الأعمدة المراد استيرادها — اختر الكل أو أعمدة محددة فقط</label>
        <div style="display:flex;gap:6px;margin-bottom:6px">
          <button type="button" class="mini-btn" onclick="ZDB._impSelectAll(true)">تحديد الكل</button>
          <button type="button" class="mini-btn" onclick="ZDB._impSelectAll(false)">إلغاء التحديد</button>
        </div>
        <div class="checklist">${r.headers.map(h=>`<label><input type="checkbox" data-impcol value="${esc(h)}" checked>${esc(h)}</label>`).join('')}</div>`;
    });
  }
  function _impSelectAll(val) { document.querySelectorAll('[data-impcol]').forEach(cb => cb.checked = val); }

  // ---------------- EXPORT ----------------
  function modalExport() {
    if (!state.table) return toast('اختر جدول أولاً', false);
    openModal('تصدير البيانات', `<p style="color:var(--muted);font-size:12.5px">سيتم تصدير كل الصفوف المطابقة للفلتر الحالي</p>`, [
      {label:'Excel / CSV', bg:'#27ae60', action: () => doExport('csv')},
      {label:'TXT', bg:'#7f8c8d', action: () => doExport('txt')},
      {label:'SQL', bg:'#d35400', action: () => doExport('sql')},
      {label:'HTML/PDF', bg:'#c0392b', action: () => doExport('html')},
    ]);
  }
  async function doExport(format) {
    const search = document.getElementById('dataSearch').value;
    const r = await api('export', { db: state.db, table: state.table, format, search });
    if (!r.ok) return toast(r.msg, false);
    closeModal();
    window.open('?download=' + r.download, '_blank');
    toast('تم تجهيز الملف');
  }

  // ---------------- ACCOUNT ----------------
  function modalAccount() {
    openModal('تغيير بيانات الحساب (خزنة مشفّرة)', `
      <label>اسم مستخدم جديد</label><input type="text" id="mAccUser">
      <label>كلمة مرور جديدة</label><input type="password" id="mAccPass">
      <label>تأكيد كلمة المرور</label><input type="password" id="mAccPass2">
    `, [{label:'حفظ', bg:'#2980b9', action: async () => {
      const user = document.getElementById('mAccUser').value.trim();
      const pass = document.getElementById('mAccPass').value;
      const pass2 = document.getElementById('mAccPass2').value;
      const r = await api('change_credentials', { user, pass, pass2 });
      if (r.ok) { closeModal(); toast('تم التحديث بنجاح'); } else toast(r.msg, false);
    }}]);
  }

  // ---------------- MODAL HELPERS (كل الأزرار تستجيب لـ Enter وليس فقط نقر الماوس) ----------------
  function openModal(title, bodyHtml, buttons, wide=false) {
    const root = document.getElementById('modalRoot');
    root.innerHTML = `
      <div class="modal-overlay" onclick="if(event.target===this) ZDB.closeModal()">
        <div class="modal ${wide?'wide':''}">
          <div class="modal-top"></div>
          <div class="modal-head"><h2>${title}</h2></div>
          <div class="modal-body">${bodyHtml}</div>
          <div class="modal-foot">
            ${buttons.map((b,i)=>`<button style="background:${b.bg}" id="mBtn${i}">${b.label}</button>`).join('')}
            <button style="background:#444" onclick="ZDB.closeModal()">إلغاء</button>
          </div>
        </div>
      </div>`;
    buttons.forEach((b,i)=>{
      document.getElementById(`mBtn${i}`).onclick = async () => {
        await b.action();
        if (!b.keepOpen && document.getElementById(`mBtn${i}`)) { /* الدالة نفسها تتحكم فى closeModal */ }
      };
    });

    if (state._modalKeyHandler) document.removeEventListener('keydown', state._modalKeyHandler);
    state._modalKeyHandler = (e) => {
      if (e.key !== 'Enter') return;
      const tag = (e.target.tagName || '').toLowerCase();
      if (tag === 'textarea') return;
      if (!document.querySelector('.modal-overlay')) return;
      e.preventDefault();
      document.getElementById('mBtn0')?.click();
    };
    document.addEventListener('keydown', state._modalKeyHandler);

    const firstField = root.querySelector('input,select');
    if (firstField) setTimeout(() => firstField.focus(), 60);
  }
  function closeModal() {
    document.getElementById('modalRoot').innerHTML = '';
    if (state._modalKeyHandler) { document.removeEventListener('keydown', state._modalKeyHandler); state._modalKeyHandler = null; }
  }

  // ---------------- THEME ----------------
  function toggleTheme() {
    state.dark = !state.dark;
    const root = document.documentElement.style;
    if (state.dark) {
      root.setProperty('--bg','#0d1117'); root.setProperty('--sidebar','#161b22');
      root.setProperty('--tree','#1c2128'); root.setProperty('--fg','#e6edf3');
    } else {
      root.setProperty('--bg','#ffffff'); root.setProperty('--sidebar','#dfe6e9');
      root.setProperty('--tree','#ffffff'); root.setProperty('--fg','#2d3436');
    }
  }

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    if (document.getElementById('loginScreen') && !document.getElementById('loginScreen').classList.contains('hidden')) login();
  });

  if (!document.getElementById('app').classList.contains('hidden')) refreshNav();

  return {
    state, login, logout, refreshNav, modalNewDb, modalNewTable, renameSelected, deleteSelected,
    loadPage, goPage, nextPage, prevPage, goLast, headerClick, headerContext, debounceSearch,
    rowClick, rowContext, modalInsertRow, editSelectedRow, deleteSelectedRows,
    modalAddColumn, clearTable, modalSort, modalColors, _pickColor, modalFunctions,
    modalGenerate, modalDuplicates, modalImport, _impSelectAll, modalExport, modalAccount,
    toggleTheme, closeModal, toggleSidebar
  };
})();
</script>
</body>
</html>