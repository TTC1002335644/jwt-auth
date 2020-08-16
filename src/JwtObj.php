<?php
namespace bang\jwt;

class JwtObj
{

    const STATUS_OK = 1;
    const STATUS_SIGNATURE_ERROR = -1;
    const STATUS_EXPIRED = -2;

    protected $alg = Jwt::ALG_METHOD_HMACSHA256; // 加密方式
    protected $iss = 'WebMan'; // 发行人
    protected $exp; // 到期时间
    protected $sub; // 主题
    protected $nbf; // 在此之前不可用
    protected $aud; // 用户
    protected $iat; // 发布时间
    protected $jti; // JWT ID用于标识该JWT
    protected $signature;
    protected $status = 0;
    protected $data;
    protected $secretKey;
    protected $header;
    protected $payload;


    protected function initialize():void
    {
        if(empty($this->nbf)){
            $this->nbf = time();
        }
        if(empty($this->iat)){
            $this->iat = time();
        }
        if(empty($this->exp)){
            $this->exp = time() + 7200;
        }
        if(empty($this->jti)){
            $this->jti = Random::character(10);
        }

        // 解包：验证签名
        if(!empty($this->signature)){
            $signature = $this->signature();
            if($this->signature !== $signature){
                $this->status = self::STATUS_SIGNATURE_ERROR;
                return;
            }
            if(time() > $this->exp){
                $this->status = self::STATUS_EXPIRED;
                return;
            }
        }
        $this->status = self::STATUS_OK;

    }

    /**
     * @return string
     */
    public function getAlg()
    {
        return $this->alg;
    }

    /**
     * @param $alg
     * @return JwtObj
     */
    public function setAlg($alg): self
    {
        $this->alg = $alg;
        return $this;
    }

    /**
     * @return string
     */
    public function getIss(): string
    {
        return $this->iss;
    }

    /**
     * @param string $iss
     * @return JwtObj
     */
    public function setIss(string $iss): self
    {
        $this->iss = $iss;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getExp()
    {
        return $this->exp;
    }

    /**
     * @param $exp
     * @return JwtObj
     */
    public function setExp($exp): self
    {
        $this->exp = $exp;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getSub()
    {
        return $this->sub;
    }

    /**
     * @param $sub
     * @return JwtObj
     */
    public function setSub($sub): self
    {
        $this->sub = $sub;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getNbf()
    {
        return $this->nbf;
    }

    /**
     * @param $nbf
     * @return JwtObj
     */
    public function setNbf($nbf): self
    {
        $this->nbf = $nbf;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getAud()
    {
        return $this->aud;
    }

    /**
     * @param $aud
     * @return JwtObj
     */
    public function setAud($aud): self
    {
        $this->aud = $aud;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getIat()
    {
        return $this->iat;
    }

    /**
     * @param $iat
     * @return JwtObj
     */
    public function setIat($iat): self
    {
        $this->iat = $iat;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getJti()
    {
        return $this->jti;
    }

    /**
     * @param $jti
     * @return JwtObj
     */
    public function setJti($jti): self
    {
        $this->jti = $jti;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * @return int
     */
    public function getStatus(): int
    {
        return $this->status;
    }

    /**
     * @param $data
     * @return JwtObj
     */
    public function setData($data): self
    {
        $this->data = $data;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getData()
    {
        return $this->data;
    }

    /**
     * @return mixed
     */
    public function getSecretKey()
    {
        return $this->secretKey;
    }

    /**
     * @param $secretKey
     * @return JwtObj
     */
    public function setSecretKey($secretKey): self
    {
        $this->secretKey = $secretKey;
        return $this;
    }

    public function setHeader()
    {
        //TODO:: 为了兼容老版本做了映射
        $algMap = [
            Jwt::ALG_METHOD_HMACSHA256 => Jwt::ALG_METHOD_HS256,
            Jwt::ALG_METHOD_AES => Jwt::ALG_METHOD_AES,
            Jwt::ALG_METHOD_HS256 => Jwt::ALG_METHOD_HS256
        ];

        $header = json_encode([
            'alg' => $algMap[$this->getAlg()],
            'typ' => 'JWT'
        ], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        $this->header = Encryption::getInstance()->base64UrlEncode($header);
    }

    /**
     * @return mixed
     */
    public function getHeader()
    {
        return $this->header;
    }

    public function setPayload()
    {
        $payload = json_encode([
            'exp' => $this->getExp(),
            'sub' => $this->getSub(),
            'nbf' => $this->getNbf(),
            'aud' => $this->getAud(),
            'iat' => $this->getIat(),
            'jti' => $this->getJti(),
            'status' => $this->getStatus(),
            'data' => $this->getData()
        ], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);

        $this->payload = Encryption::getInstance()->base64UrlEncode($payload);
    }

    /**
     * @return mixed
     */
    public function getPayload()
    {
        return $this->payload;
    }

    public function signature():?string
    {

        $this->setHeader();
        $this->setPayload();

        $content = $this->getHeader() . '.' . $this->getPayload();

        switch ($this->getAlg()){
            case Jwt::ALG_METHOD_HMACSHA256:
                $signature = Encryption::getInstance()->base64UrlEncode(
                    hash_hmac('sha256', $content, $this->getSecretKey(), true)
                );
                break;
            case Jwt::ALG_METHOD_HS256:
                $signature = Encryption::getInstance()->base64UrlEncode(
                    hash_hmac('sha256', $content, $this->getSecretKey(), true)
                );
                break;
            case Jwt::ALG_METHOD_AES:
                $signature = Encryption::getInstance()->base64UrlEncode(
                    openssl_encrypt($content, 'AES-128-ECB', $this->getSecretKey())
                );
                break;
        }

        return $signature;
    }

    public function __toString()
    {
        $this->signature = $this->signature();
        return $this->header . '.' . $this->payload . '.' . $this->signature;
    }


}