# jwt
JSON Web Token（JWT）是目前跨域身份验证解决方案。本人也封装了一个小小插件

# 安装
```
composer require bang/jwt
```
    

# 实例代码


```
<?php
use bang\jwt\Jwt;
        
class Index
{
    public function test()
    {
            $jwtObject = Jwt::getInstance()->publish();
            $jwtObject->setAlg('HMACSHA256'); // 加密方式
            $jwtObject->setAud('user'); // 用户
            $jwtObject->setExp(time()+3600); // 过期时间
            $jwtObject->setIat(time()); // 发布时间
            $jwtObject->setIss('bang'); // 发行人
            $jwtObject->setJti(md5(time())); // jwt id 用于标识该jwt
            $jwtObject->setNbf(time()+60*5); // 在此之前不可用
            $jwtObject->setSub('主题'); // 主题
            // 自定义数据
            $jwtObject->setData([
                'user_id' => 1
            ]);
    
            // 最终生成的token
            $token = $jwtObject->create();
    
            echo $token;
    
            //解密token
            $data = Jwt::getInstance()->decode($token);
    
            var_dump($data);
    }

}
```

 
