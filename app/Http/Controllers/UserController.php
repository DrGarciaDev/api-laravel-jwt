<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Auth;

use Carbon\Carbon;

class UserController extends Controller
{
     /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        // $this->middleware('jwt.personalizado', ['only' => ['getAuthenticatedUser', 'refreshToken']]);
        $this->middleware('jwt.auth', ['only' => ['getAuthenticatedUser', 'refreshToken']]);
    }

    public function login(Request $request, $recuerdame  = false)
    {
        $credentials = $request->only('email', 'password');

        $validator = Validator::make($request->all(), [
            'email'    => 'required|string|email|max:255',
            'password' => 'required|string|min:6',
        ]);

        if($validator->fails()){
            return response()->json([
                'success' => false,
                'message' => 'Falló la validación',
                'error'   => $validator->errors()
            ], 422);
        }
        
        if ($recuerdame) {
            $expiration_token = 1;
            JWTAuth::factory()->setTTL($expiration_token);
        }

        try {
            if ( ! $token = JWTAuth::attempt($credentials) ) {
                return response()->json(['error' => 'invalid_credentials'], 401);
            }
            
            return response()->json([
                'success'     => true,
                'token'       => $token,
                'user'        => User::where('email', $credentials['email'])->first()
            ], 200);

        } catch (JWTException $e) {
            return response()->json(['error' => 'could_not_create_token'], 500);
        }   

    }

    public function refreshToken()
    {        
        try {
            $token = JWTAuth::refresh(JWTAuth::getToken());

            return response()->json([
                'success' => true,
                'token'   => $token
            ], 200);

        } catch (TokenExpiredException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Falló la validación, logueate nuevamente (TokenExpired)'
            ], 422);
        } catch (TokenBlacklistedException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Falló la validación, logueate nuevamente (TokenBlacklisted)'
            ], 422);
        } catch (JWTException $e) {
            return response()->json(['error' => 'No se pudo refrescar el token'], 500);
        }
    }

    public function getAuthenticatedUser()
    {
        try {
            if ( ! $user = JWTAuth::parseToken()->authenticate() ) {
                return response()->json(['user_not_found'], 404);
            }
        } catch (TokenExpiredException $e) {
            return response()->json(['error' => 'token_expired'], 401);
        } catch (TokenInvalidException $e) {
            return response()->json(['error' => 'token_invalid'], 401);
        } catch (JWTException $e) {
            return response()->json(['error' => 'token_absent'], 401);
        }

        return response()->json(['user' => $user]);
    }


    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'     => 'required|string|max:255',
            'email'    => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if($validator->fails()){
            return response()->json([
                'success' => false,
                'message' => 'Falló la validación',
                'error'   => $validator->errors()
            ], 422);
        }

        $user = User::create([
            'name'     => $request->get('name'),
            'email'    => $request->get('email'),
            'password' => Hash::make($request->get('password')),
        ]);

        $token = JWTAuth::fromUser($user);

        return response()->json([
            'success' => false,
            'user'    => $user,
            'token'   => $token
        ], 201);
    }

    public function logout(Request $request) {
        $token = JWTAuth::getToken();

        try {
            $token = JWTAuth::invalidate($token);

            return response()->json([
                'success' => true,
                'message' => 'Logout success'
            ], 200);

        } catch (JWTException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Logout failed'
            ], 422);
        }
    }
}
