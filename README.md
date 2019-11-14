

        $cas = new \PhpCasCore\Cas(env("CAS_SERVER"), env("CAS_PATH"), env("WEB_HOST"));
        $func = function ($url) {
            getGouuseCore()->ResponseLib->redirect($url);
        };
        $cas->setRequest($request->input(), $request->server());
        $cas->setRedirectCall($func);
        try {
            $member_code = $cas->isAuthenticated(); 
         } catch (\Exception $e) {
         
         }