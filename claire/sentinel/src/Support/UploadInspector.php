<?php

namespace Claire\Sentinel\Support;

use Illuminate\Http\UploadedFile;
use ZipArchive;

class UploadInspector
{
    /**
     * Returns a reason string when the upload must be rejected, null when it is fine.
     *
     * @param bool $allowCode accept archives that contain scripts (addon/update packages)
     */
    public function inspect(UploadedFile $file, bool $allowCode = false): ?string
    {
        $name = (string) $file->getClientOriginalName();

        if ($reason = $this->inspectName($name)) {
            return $reason;
        }

        $path = $file->getRealPath();
        if ($path === false || ! is_file($path)) {
            return null;
        }

        $content = (string) @file_get_contents($path, false, null, 0, (int) config('sentinel.uploads.max_scan_bytes', 20971520));

        if (str_starts_with($content, "\x7fELF") || str_starts_with($content, "MZ\x90\x00")) {
            return 'executable binary';
        }

        $isZip = str_starts_with($content, "PK\x03\x04") || str_starts_with($content, "PK\x05\x06");

        if (! $isZip && Signatures::containsPhp($content)) {
            return 'file contains PHP code';
        }

        if ($isZip) {
            return $this->inspectZip($path, $allowCode);
        }

        return null;
    }

    public function inspectName(string $name): ?string
    {
        if ($name === '' || str_contains($name, "\0")) {
            return 'invalid file name';
        }
        if (preg_match('#(\.\.|[/\\\\])#', $name)) {
            return 'path characters in file name';
        }

        $lower = strtolower($name);
        if (in_array($lower, array_map('strtolower', (array) config('sentinel.uploads.blocked_filenames', [])), true)) {
            return 'forbidden file name';
        }

        // Every extension segment counts: "shell.php.jpg" and "x.phtml" are both rejected.
        $segments = explode('.', $lower);
        array_shift($segments);
        $blocked = (array) config('sentinel.uploads.blocked_extensions', []);
        foreach ($segments as $segment) {
            if (in_array(trim($segment), $blocked, true)) {
                return "forbidden extension .{$segment}";
            }
        }

        return null;
    }

    public function inspectZip(string $path, bool $allowCode = false): ?string
    {
        if (! class_exists(ZipArchive::class)) {
            return null;
        }

        $zip = new ZipArchive();
        if ($zip->open($path) !== true) {
            return 'unreadable archive';
        }

        try {
            if ($zip->numFiles > (int) config('sentinel.uploads.max_archive_entries', 5000)) {
                return 'archive has too many entries';
            }

            $blockedNames = array_map('strtolower', (array) config('sentinel.uploads.blocked_filenames', []));

            for ($i = 0; $i < $zip->numFiles; $i++) {
                $entry = (string) $zip->getNameIndex($i);
                $normalized = str_replace('\\', '/', $entry);

                // Zip Slip: "../x.php", "/etc/x", "C:/x"
                if (str_starts_with($normalized, '/') || preg_match('#(^|/)\.\.(/|$)#', $normalized) || preg_match('#^[a-z]:#i', $normalized)) {
                    return "archive path traversal ({$entry})";
                }

                if (in_array(strtolower(basename($normalized)), $blockedNames, true)) {
                    return "archive contains " . basename($normalized);
                }

                if ($allowCode) {
                    continue;
                }

                if (Signatures::isScriptName($normalized)) {
                    return "archive contains script ({$entry})";
                }

                $stat = $zip->statIndex($i);
                if ($stat && $stat['size'] > 0 && $stat['size'] <= 2 * 1024 * 1024) {
                    $data = (string) $zip->getFromIndex($i);
                    if (Signatures::containsPhp($data)) {
                        return "archive entry contains PHP code ({$entry})";
                    }
                }
            }
        } finally {
            $zip->close();
        }

        return null;
    }
}
