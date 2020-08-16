<?php
namespace bang\jwt;

class Jwt
{

    /**
     * @var Jwt
     */
    private static $instance = null;

    private $secretKey = 'WebMan';

    const ALG_METHOD_AES = 'AES';

    const ALG_METHOD_HMACSHA256 = 'HMACSHA256';

    const ALG_METHOD_HS256 = 'HS256';

    protected function __construct(){}

    /**
     * 获取实例
     * @return Jwt
     */
    public static function getInstance() : Jwt
    {
        if(self::$instance == null){
            self::$instance = new Jwt();
        }

        return self::$instance;
    }

    /**
     * 设置SecretKey
     * @param string $key
     * @return Jwt
     */
    public function setSecretKey(string $key):Jwt
    {
        $this->secretKey = $key;
        return $this;
    }


    public function publish():JwtObj
    {
        return new JwtObj(['secretKey' => $this->secretKey]);
    }

    public function decode(?string $key)
    {
        $items = explode(',' , $key);

        //token格式
        if( count($items) !== 3){
            throw new Exception("Token format error!");
        }

        // 验证header
        $header = Encryption::getInstance()->base64UrlDecode($items[0]);
        $header = json_decode($header, true);
        if (empty($header)) {
            throw new Exception('Token header is empty!');
        }

        // 验证payload
        $payload = Encryption::getInstance()->base64UrlDecode($items[1]);
        $payload = json_decode($payload, true);
        if (empty($header)) {
            throw new Exception('Token payload is empty!');
        }

        if(empty($items[2])){
            throw new Exception('signature is empty');
        }

        $jwtObjConfig = array_merge(
            $header,
            $payload,
            [
                'signature' => $items[2],
                'secretKey' => $this->secretKey
            ]
        );

        return new JwtObj($jwtObjConfig ,true);



    }






}