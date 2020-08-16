<?php
namespace bang\jwt;


class Encryption
{
    /**
     * @var null
     */
    private static $instance = null;

    function __construct()
    {
    }

    /**
     * 获取实例
     * @param mixed ...$args
     * @return Encryption|null
     */
    public static function getInstance(...$args)
    {
        if(self::$instance == null){
            self::$instance = new static(...$args);
        }
        return self::$instance;
    }

    public function base64UrlEncode($content)
    {
        return str_replace('=', '', strtr(base64_encode($content), '+/', '-_'));
    }

    public function base64UrlDecode($content)
    {
        $remainder = strlen($content) % 4;
        if ($remainder) {
            $addlen = 4 - $remainder;
            $content .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($content, '-_', '+/'));
    }

}