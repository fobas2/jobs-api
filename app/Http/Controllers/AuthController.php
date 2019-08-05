<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use App\User;
use App\Notifications\SignupActivate;
use Avatar;
use Storage;

class AuthController extends Controller
{
    /**
     * @OA\Post(
     *     path="/auth/signup",
     *     tags={"Auth"},
     *     summary="Create user",
     *     description="Signup new user and send verification token",
     *     operationId="createUser",
     *     @OA\RequestBody(
     *         description="Create user object",
     *         required=true,
     *         @OA\MediaType(
     *              mediaType="application/json",
     *              @OA\Schema(
     *                 title="User signup",
     *                 description="Model user account",
     *                 @OA\Property(
     *                      property="name",
     *                      type="string",
     *                      example="fobas2"
     *                 ),
     *                 @OA\Property(
     *                      property="email",
     *                      type="string",
     *                      example="azyav4ikoff@yandex.by"
     *                 ),
     *                 @OA\Property(
     *                      property="password",
     *                      type="string",
     *                      example="123478569"
     *                 ),
     *                 @OA\Property(
     *                      property="password_confirmation",
     *                      type="string",
     *                      example="123478569"
     *                 ),
     *                 @OA\Property(
     *                      property="profile",
     *                      type="string",
     *                      example="none"
     *                 )
     *              )
     *         )
     *     ),
     *     @OA\Response(
     *         response="201",
     *         description="Successfully created user!",
     *         @OA\JsonContent(ref="#/components/schemas/User")
     *     )
     * )
     */

    /**
     * Create user
     *
     * @param  [string] name
     * @param  [string] email
     * @param  [string] password
     * @param  [string] password_confirmation
     * @return [string] message
     */

    public function signup(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed',
            'profile' => 'string'
        ]);
        $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
            'activation_token' => str_random(60),
            'profile' => $request->profile
        ]);
        $user->save();

        $avatar = Avatar::create($user->name)->getImageObject()->encode('png');
        Storage::put('avatars/'.$user->id.'/avatar.png', (string) $avatar);


        $user->notify(new SignupActivate($user));

        return response()->json([
            'activation_token' => $user->activation_token,
            'message' => 'Successfully created user!'
        ],201);
    }

    /**
     * @OA\Get(
     *     path="/auth/signup/activate/{token}",
     *     tags={"Auth"},
     *     summary="Activate user",
     *     description="Activate new signup user.",
     *     operationId="activateUser",
     *     @OA\Parameter(
     *         name="token",
     *         in="path",
     *         description="Veryfication email token",
     *         required=true,
     *         @OA\Schema(
     *             type="string"
     *         )
     *     ),
     *     @OA\Response(
     *         response=202,
     *         description="This activation token is accepted.",
     *         @OA\JsonContent(ref="#/components/schemas/User"),
     *     ),
     *     @OA\Response(
     *         response="404",
     *         description="This activation token is invalid."
     *     )
     * )
     */

    public function signupActivate($token)
    {
        $user = User::where('activation_token', $token)->first();
        if (!$user) {
            return response()->json([
                'message' => 'This activation token is invalid.'
            ], 404);
        }
        $user->active = true;
        $user->activation_token = '';
        $user->save();
        return response()->json([
            'User' => $user,
            'message' => 'User account activation.'
        ],202);
    }

    /**
     * @OA\Post(
     *     path="/auth/login",
     *     tags={"Auth"},
     *     summary="Login user into system",
     *     operationId="loginUser",
     *     @OA\RequestBody(
     *         description="Create user object",
     *         required=true,
     *         @OA\MediaType(
     *              mediaType="application/json",
     *              @OA\Schema(
     *                 title="User login",
     *                 description="User login account",
     *                 @OA\Property(
     *                      property="email",
     *                      type="string",
     *                      example="azyav4ikoff@yandex.by"
     *                 ),
     *                 @OA\Property(
     *                      property="password",
     *                      type="string",
     *                      example="123478569"
     *                 ),
     *                 @OA\Property(
     *                      property="remember_me",
     *                      type="boolean",
     *                      example=true
     *                 )
     *              )
     *         )
     *     ),
     *     @OA\Response(
     *         response="200",
     *         description="User login.",
     *         @OA\JsonContent(ref="#/components/schemas/User")
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Invalid username/password supplied"
     *     )
     * )
     */

    /**
     * Login user and create token
     *
     * @param  [string] email
     * @param  [string] password
     * @param  [boolean] remember_me
     * @return [string] access_token
     * @return [string] token_type
     * @return [string] expires_at
     */

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);
        $credentials = request(['email', 'password']);
        $credentials['active'] = 1;
        $credentials['deleted_at'] = null;
        if(!Auth::attempt($credentials))
            return response()->json([
                'message' => 'Invalid username/password supplied'
            ],401);
        $user = $request->user();
        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        if ($request->remember_me)
            $token->expires_at = Carbon::now()->addWeeks(1);
        $token->save();
        return response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse(
                $tokenResult->token->expires_at
            )->toDateTimeString(),
            'message' => 'User login.'
        ],200);
    }

    /**
     * @OA\Get(
     *     path="/auth/user",
     *     tags={"Auth"},
     *     summary="The login user",
     *     security={{"bearerAuth":{}}},
     *     operationId="theUser",
     *     @OA\Response(
     *         response=200,
     *         description="User login.",
     *         @OA\JsonContent(ref="#/components/schemas/User")
     *     )
     * )
     */

    /**
     * Get the authenticated User
     *
     * @return [json] user object
     */
    public function user(Request $request)
    {
        return response()->json([
            $request->user()
        ],200);
    }

    /**
     * @OA\Get(
     *     path="/auth/logout",
     *     tags={"Auth"},
     *     summary="Logout user",
     *     description="Logout user, revoke the token",
     *     security={{"bearerAuth":{}}},
     *     operationId="logoutUser",
     *     @OA\Response(
     *         response=200,
     *         description="Successfully logged out."
     *     )
     * )
     */

    /**
     * Logout user (Revoke the token)
     *
     * @return [string] message
     */
    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json([
            'message' => 'Successfully logged out.'
        ],200);
    }

}