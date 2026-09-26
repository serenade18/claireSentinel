<?php

namespace Claire\Sentinel\Support;

/**
 * Malware signatures, drawn largely from the shells found on this site in 2026.
 */
class Signatures
{
    /** Extensions Apache/PHP-FPM may execute (also matched as a middle extension, e.g. x.php.jpg). */
    public const SCRIPT_EXTENSIONS = 'php[0-9]*|pht|phtml|phar|phps|inc|cgi|pl|py|sh|asp|aspx|jsp|shtml';

    /**
     * Patterns that mark PHP source as malicious.
     *
     * @param bool $strongOnly only patterns with no legitimate use (for third-party code in vendor/,
     *                         where e.g. template engines legitimately eval compiled PHP)
     */
    public static function php(bool $strongOnly = false): array
    {
        $strong = [
            'encoded-eval' => '#(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|strrev|convert_uudecode)\s*\(#i',
            'input-exec' => '#(eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*(@\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)#i',
            'input-callable' => '#\$\{?\s*_(GET|POST|REQUEST|COOKIE)\s*\}?\s*\[[^\]]+\]\s*\(#i',
            'split-wrapper' => '#include\s+implode\s*\(#i',
            'reflection-shell' => '#openssl_decrypt\s*\([^;]*session_id\s*\(#i',
            'env-harvester' => '#glob\s*\(\s*["\']/(home|var/www)/\*[^"\']*\.env#i',
            'known-ioc' => '#(pamist\.cyou|rohdempresarial|mrnewjibon|AVRIL_JANCOK|moneroocean|stratum\+tcp|xmrig|lao\.zi|white-url-zi|localXorEncryptDecrypt)#i',
        ];
        if ($strongOnly) {
            return $strong;
        }

        return $strong + [
            'remote-eval' => '#eval\s*\(\s*["\']\?>["\']\s*\.#i',
            'stream-include' => '#(include|require)(_once)?\s*\(?\s*["\'](zip|phar|data|expect|php)://#i',
            'preg-e' => '#preg_replace\s*\(\s*["\']([\#/~|@!%])[^"\']*\1[imsxuADSUXJ]*e[imsxuADSUXJ]*["\']\s*,#',
            'create-function' => '#create_function\s*\(#i',
        ];
    }

    /** Patterns that mark an .htaccess as an attacker "lock" or allow-list file. */
    public static function htaccess(): array
    {
        return [
            'lock-allowlist' => '#<FilesMatch\s+[\'"]\^\(index\.php\)\$[\'"]>#i',
            'shell-allowlist' => '#<FilesMatch\s+["\']\^\([^)]*\.php[^)]*\)\$["\']>\s*(Order\s+allow,deny\s*)?Allow\s+from\s+all#i',
            'handler-remap' => '#(AddHandler|AddType|SetHandler)\s+[^\n]*(php|x-httpd)[^\n]*\s\.(jpg|jpeg|png|gif|webp|txt|ico|zip)\b#i',
            'auto-prepend' => '#php_value\s+auto_(prepend|append)_file#i',
        ];
    }

    /** Request input that should never be sent to this application. */
    public static function input(): array
    {
        return [
            'stream-wrapper' => '#\b(zip|phar|php|expect|data|glob|file)://#i',
            'php-open-tag' => '#<\?(php\b|=)#i',
            'traversal' => '#(\.\./|\.\.\\\\|%2e%2e%2f|%2e%2e/|\.\.%2f)#i',
            'null-byte' => '#\x00#',
        ];
    }

    /** True when $content (any file type) carries executable PHP. */
    public static function containsPhp(string $content): bool
    {
        if (preg_match('#<\?php\b#i', $content)) {
            return true;
        }
        // Short echo tags only count when followed by code (binary images contain "<?=" by chance).
        return (bool) preg_match('#<\?=\s*(\$|["\'][^"\']*["\']\s*;|[a-z_]+\s*\()#i', $content)
            || (bool) preg_match('#__halt_compiler\s*\(#i', $content);
    }

    public static function match(string $content, array $patterns): ?string
    {
        foreach ($patterns as $name => $pattern) {
            if (preg_match($pattern, $content)) {
                return $name;
            }
        }
        return null;
    }

    public static function isScriptName(string $path): bool
    {
        return (bool) preg_match('#\.(' . self::SCRIPT_EXTENSIONS . ')(\.|$)#i', basename($path));
    }
}
