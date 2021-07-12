<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

use JWTAuth;
use Exception;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;

class JwtMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (Exception $e) {
            if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenInvalidException){
                return response()->json(['status' => 'Token is Invalid']);
            }
            else if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException){
                // If the token is expired, then it will be refreshed and added to the headers
                // try
                // {
                //     $refreshed = JWTAuth::refresh(JWTAuth::getToken());
                //     $user      = JWTAuth::setToken($refreshed)->toUser();
                //     header('Authorization: Bearer ' . $refreshed);
                // }
                // catch (Exception $e)
                // {
                //     if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException) {
                //         return response()->json(['status' => 'Refresh Token is Expired'],401);
                //     }else{
                //         return response()->json(['status' => $e],400);
                //     }
                // }

                return response()->json(['status' => 'Token is Expired']);
            }else{
                return response()->json(['status' => 'Authorization Token not found']);
            }
        }
        
        return $next($request);
    }
}
