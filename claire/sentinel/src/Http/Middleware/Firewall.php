<?php

namespace Claire\Sentinel\Http\Middleware;

use Claire\Sentinel\Support\Alerter;
use Claire\Sentinel\Support\IpBanner;
use Claire\Sentinel\Support\Signatures;
use Claire\Sentinel\Support\UploadInspector;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Symfony\Component\HttpFoundation\Response;

class Firewall
{
    public function __construct(
        private IpBanner $banner,
        private UploadInspector $uploads,
        private Alerter $alerter,
    ) {
    }

    public function handle(Request $request, Closure $next)
    {
        if (! config('sentinel.enabled', true)) {
            return $next($request);
        }

        $ip = (string) $request->ip();
        if ($this->banner->isAllowed($ip)) {
            return $next($request);
        }

        if ($this->banner->isBanned($ip)) {
            return $this->deny();
        }

        $path = ltrim(rawurldecode($request->path()), '/');

        foreach ((array) config('sentinel.firewall.honeypot_paths', []) as $pattern) {
            if (preg_match($pattern, $path)) {
                return $this->block($request, 'honeypot', "Backdoor path requested: /{$path}", ban: true, alert: true);
            }
        }

        foreach ((array) config('sentinel.firewall.blocked_paths', []) as $pattern) {
            if (preg_match($pattern, $path)) {
                return $this->block($request, 'probe', "Blocked path: /{$path}");
            }
        }

        // Traversal is checked in the URL only: editors legitimately post "../" inside HTML.
        $query = rawurldecode((string) $request->getQueryString());
        if ($query !== '' && ($hit = Signatures::match($query, Signatures::input()))) {
            return $this->block($request, 'malicious-input', "Query string matched {$hit}");
        }

        if (! $this->skipInputInspection($path)) {
            $patterns = Signatures::input();
            unset($patterns['traversal']);
            if ($hit = $this->scanInput($request->request->all(), $patterns)) {
                return $this->block($request, 'malicious-input', "Request body matched {$hit}", alert: true);
            }
        }

        if ($request->files->count() > 0) {
            $allowCode = $this->codeArchivesAllowed($request, $path);
            foreach ($this->flattenFiles($request->allFiles()) as $file) {
                if ($reason = $this->uploads->inspect($file, $allowCode)) {
                    return $this->block($request, 'upload', "Upload rejected ({$reason}): " . $file->getClientOriginalName(), weight: 3, alert: true);
                }
            }
        }

        return $next($request);
    }

    private function block(Request $request, string $type, string $message, bool $ban = false, int $weight = 1, bool $alert = false): Response
    {
        $ip = (string) $request->ip();
        $banned = $ban ? $this->banner->isBannable($ip) : $this->banner->strike($ip, $weight);
        if ($ban) {
            $this->banner->ban($ip);
        }

        $this->alerter->record($type, $message, [
            'ip' => $ip,
            'method' => $request->method(),
            'url' => $request->fullUrl(),
            'user_agent' => (string) $request->userAgent(),
            'user_id' => optional($request->user())->id,
            'banned' => $banned,
        ], $alert || $banned);

        return $this->deny();
    }

    private function deny(): Response
    {
        return response('Forbidden', 403, ['Content-Type' => 'text/plain', 'Cache-Control' => 'no-store']);
    }

    private function skipInputInspection(string $path): bool
    {
        foreach ((array) config('sentinel.firewall.skip_input_inspection', []) as $pattern) {
            if (preg_match($pattern, $path)) {
                return true;
            }
        }
        return false;
    }

    private function scanInput(array $input, array $patterns, int $depth = 0): ?string
    {
        if ($depth > 10) {
            return null;
        }
        foreach ($input as $key => $value) {
            if (is_array($value)) {
                if ($hit = $this->scanInput($value, $patterns, $depth + 1)) {
                    return $hit;
                }
            } elseif (is_string($value) || is_string($key)) {
                $haystack = $key . '=' . (is_scalar($value) ? (string) $value : '');
                if ($hit = Signatures::match($haystack, $patterns)) {
                    return "{$hit} in '{$key}'";
                }
            }
        }
        return null;
    }

    private function codeArchivesAllowed(Request $request, string $path): bool
    {
        if (env('ALLOW_CODE_UPLOADS') !== true) {
            return false;
        }
        $user = $request->user();
        $role = config('sentinel.admin.role_attribute', 'user_type');
        if (! $user || ($user->{$role} ?? null) !== 'admin') {
            return false;
        }
        foreach ((array) config('sentinel.uploads.code_archive_paths', []) as $pattern) {
            if (preg_match($pattern, $path)) {
                return true;
            }
        }
        return false;
    }

    /** @return UploadedFile[] */
    private function flattenFiles(array $files): array
    {
        $flat = [];
        array_walk_recursive($files, function ($file) use (&$flat) {
            if ($file instanceof UploadedFile) {
                $flat[] = $file;
            }
        });
        return $flat;
    }
}
