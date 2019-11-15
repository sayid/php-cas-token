目前只支持cas2.0

        $cas = new \PhpCasCore\Cas(env("CAS_SERVER"), env("CAS_PATH"));
        $func = function ($url) {
            getGouuseCore()->ResponseLib->redirect($url);
        };
        //回调的地址
        $cas->callBackUrl("http://127.0.0.1/user_center/auth-cas");
        //需要携带的参数
        $cas->setQueryString($request->getQueryString() ?? "");
        $cas->setRequest($request->input(), $request->server());
        $cas->setRedirectCall($func);
        try {
            $user = $cas->isAuthenticated();
            if ($user) {
                //单点登录成功
            }
         } catch (\Exception $e) {
         
         }
         //单点登录失败