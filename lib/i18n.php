<?php
declare(strict_types=1);

// Translations: English strings are the keys; lang/<code>.php maps them to the target language.

const SHIELD_LANGUAGES = ['en' => 'English', 'bg' => 'Български'];

function shield_lang(?string $set = null): string
{
    static $lang = null;
    if ($set !== null) {
        $lang = isset(SHIELD_LANGUAGES[$set]) ? $set : 'en';
        return $lang;
    }
    if ($lang === null) {
        $pref = 'auto';
        if (function_exists('shield_installed') && shield_installed()) {
            try {
                $pref = (string)(shield_config()['language'] ?? 'auto');
            } catch (Throwable) {
            }
        }
        if ($pref === 'auto' || !isset(SHIELD_LANGUAGES[$pref])) {
            $accept = strtolower((string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''));
            $pref = 'en';
            foreach (array_keys(SHIELD_LANGUAGES) as $code) {
                if (str_starts_with($accept, $code)) {
                    $pref = $code;
                }
            }
        }
        $lang = $pref;
    }
    return $lang;
}

/** Translate, then sprintf() with the remaining arguments. */
function __(string $text, mixed ...$args): string
{
    static $tables = [];
    $lang = shield_lang();
    if ($lang !== 'en') {
        $tables[$lang] ??= (array)(@include dirname(__DIR__) . '/lang/' . $lang . '.php');
        $text = (string)($tables[$lang][$text] ?? $text);
    }
    return $args ? vsprintf($text, $args) : $text;
}
