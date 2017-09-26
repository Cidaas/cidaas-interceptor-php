<?php

namespace cidaas\interceptor\lib;

use Closure;
use GuzzleHttp\Client;

class Interceptor
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */

    public function handle($request, Closure $next)
    {


        $token_url = env('CIDAAS_USER_INFO_BY_TOKEN', null);

        if($token_url==null){
            return response()->json(["error"=>"Access denied for this resource"], 401);;
        }

        $access_token_key = "access_token";

        $access_token = null;

        if( $request->headers->has($access_token_key)) {
            $access_token = $request->headers->get($access_token_key);
        }

        if($access_token==null && $request->query($access_token_key) != null){
            $access_token = $request->query($access_token_key);
        }

        if($access_token==null && $request->headers->has("authorization")){
            $auth = $request->headers->get("authorization");

            if(strtolower(substr($auth, 0, strlen("bearer"))) === "bearer"){
                $authvals = explode(" ",$auth);

                if(sizeof($authvals)>1){
                    $access_token = $authvals[1];
                }
            }
        }

        //dd($request->cookies->get("cidaas_access_token"));
        $cookieRequest = false;
        if($access_token==null && $request->cookies->get("cidaas_access_token")){
            $access_token = $request->cookies->get("cidaas_access_token");
            $cookieRequest = true;
        }


        if($access_token == null)
        {
            return response()->json(["error"=>"Access denied for this resource"], 401);;
        }



        $ipAddress = "";

        if($request->headers->has("x-forwarded-for")){
            $ips = explode(" ",$request->headers->get("x-forwarded-for"));
            $ipAddress = explode(",",$auth)[0];
        }


        $host = "";

        if($request->headers->has("X-Forwarded-Host")){
            $host = $request->headers->get("X-Forwarded-Host");
        }

        $acceptLanguage = "";

        if($request->headers->has("Accept-Language")){
            $acceptLanguage = $request->headers->get("Accept-Language");
        }

        $userAgent = "";

        if($request->headers->has("user-agent")){
            $userAgent = $request->headers->get("user-agent");
        }

        $referrer = "";

        if($request->headers->has("referrer")){
            $referrer = $request->headers->get("referrer");
        }

        $allHeaders = [];
        foreach ($request->headers as $key=>$value){
            $allHeaders[$key] = $value[0];
        }



        $dataToSend = [
            "accessToken"=>$access_token,
            "userId"=>null,
            "clientId"=>null,
            "referrer"=>$referrer,
            "ipAddress"=>$ipAddress,
            "host"=>$host,
            "acceptLanguage"=>$acceptLanguage,
            "userAgent"=>$userAgent,
            "requestURL"=>"",
            "success"=>false,
            "requestedScopes"=>"",
            "requestedRoles"=>"",
            "createdTime"=>date_create('now')->format('Y-m-d\TH:i:sO'),
            "requestInfo"=>$allHeaders
        ];




        $roles = $request->route()->getAction("roles");

        if($roles!=null){
            $dataToSend["requestedRoles"] =  implode(",",$roles);
        }

        $scopes = $request->route()->getAction("scopes");

        if($scopes!=null){
            $dataToSend["requestedScopes"] =  implode(" ",$scopes);
        }


        $client = new Client();

        $result = $client->post($token_url,[
            "json"=>$dataToSend,
            "headers"=>[
                "Content-Type" => "application/json",
                "access_token"=>$access_token
            ]
        ]);

        if($result->getStatusCode() == 200) {
            $token_check_response = json_decode($result->getBody()->getContents());
            $request->headers->add([
                "__userId" =>  $token_check_response->userId,
                "__access_token" =>  $access_token
            ]);

            return $next($request);

        }else{
            if($cookieRequest){
                return response()->json(["error"=>"Access denied for this resource"], 401)->withCookie(cookie("cidaas_access_token",null));
            }
        }

        return response()->json(["error"=>"Access denied for this resource"], 401);

    }
}
