<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Carbon\Carbon;
use App\Notifications\PasswordResetRequest;
use App\Notifications\PasswordResetSuccess;
use App\User;
use App\PasswordReset;

class PasswordResetController extends Controller
{
    /**
     * @OA\Post(
     *     path="/auth/password/create",
     *     tags={"Auth"},
     *     summary="Send password reset token",
     *     description="Send password reset token on email.",
     *     security={{"bearerAuth":{}}},
     *     operationId="SendPassUserReset",
     *     @OA\RequestBody(
     *         description="User email",
     *         required=true,
     *         @OA\MediaType(
     *              mediaType="application/json",
     *              @OA\Schema(
     *                 title="User email",
     *                 description="User email account",
     *                 @OA\Property(
     *                      property="email",
     *                      type="string",
     *                      example="azyav4ikoff@yandex.by"
     *                 )
     *              )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="We have e-mailed your password reset link!"
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="We can't find a user with that e-mail address."
     *     )
     * )
     */

    /**
     * Create token password reset
     *
     * @param  [string] email
     * @return [string] message
     */
    public function create(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
        ]);
        $user = User::where('email', $request->email)->first();
        if (!$user)
            return response()->json([
                'message' => "We can't find a user with that e-mail address."
            ], 404);
        $passwordReset = PasswordReset::updateOrCreate(
            ['email' => $user->email],
            [
                'email' => $user->email,
                'token' => str_random(60)
             ]
        );
        if ($user && $passwordReset)
            $user->notify(
                new PasswordResetRequest($passwordReset->token)
            );
        return response()->json([
            $passwordReset->token,
            'message' => 'We have e-mailed your password reset link!'
        ],200);
    }

    /**
     * @OA\Get(
     *     path="/auth/password/find/{token}",
     *     tags={"Auth"},
     *     summary="Find password reset token",
     *     security={{"bearerAuth":{}}},
     *     operationId="findToken",
     *     @OA\Parameter(
     *         name="token",
     *         in="path",
     *         description="Reset password email token",
     *         required=true,
     *         @OA\Schema(
     *             type="string"
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Tokken is valid"
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="This password reset token is invalid."
     *     )
     * )
     */

    /**
     * Find token password reset
     *
     * @param  [string] $token
     * @return [string] message
     * @return [json] passwordReset object
     */
    public function find($token)
    {
        $passwordReset = PasswordReset::where('token', $token)
            ->first();
        if (!$passwordReset)
            return response()->json([
                'message' => 'This password reset token is invalid.'
            ], 404);
        if (Carbon::parse($passwordReset->updated_at)->addMinutes(720)->isPast()) {
            $passwordReset->delete();
            return response()->json([
                'message' => 'This password reset token is invalid.'
            ], 404);
        }
        return response()->json([
            $passwordReset
        ],200);
    }

    /**
     * @OA\Post(
     *     path="/auth/password/reset",
     *     tags={"Auth"},
     *     summary="Password reset",
     *     description="User password reset",
     *     security={{"bearerAuth":{}}},
     *     operationId="passUserReset",
     *     @OA\RequestBody(
     *         description="User email",
     *         required=true,
     *         @OA\MediaType(
     *              mediaType="application/json",
     *              @OA\Schema(
     *                 title="User pass reset",
     *                 description="User password reset",
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
     *                      property="token",
     *                      type="string",
     *                      example="2m2OfZXLacYl4YKWKsZuXCv0lhVW8MFBNi1agv4MVSrApQCu16czxif6dUqH"
     *                 )
     *              )
     *         )
     *
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="The user password reset"
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="We can't find a user with that e-mail address."
     *     ),
     *     @OA\Response(
     *         response=408,
     *         description="This password reset token is invalid."
     *     )
     * )
     */

     /**
     * Reset password
     *
     * @param  [string] email
     * @param  [string] password
     * @param  [string] password_confirmation
     * @param  [string] token
     * @return [string] message
     * @return [json] user object
     */
    public function reset(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string|confirmed',
            'token' => 'required|string'
        ]);
        $passwordReset = PasswordReset::where([
            ['token', $request->token],
            ['email', $request->email]
        ])->first();
        if (!$passwordReset)
            return response()->json([
                'message' => 'This password reset token is invalid.'
            ], 408);
        $user = User::where('email', $passwordReset->email)->first();
        if (!$user)
            return response()->json([
                'message' => "We can't find a user with that e-mail address."
            ], 404);
        $user->password = bcrypt($request->password);
        $user->save();
        $passwordReset->delete();
        $user->notify(new PasswordResetSuccess($passwordReset));
        return response()->json([
            $user,
            'message' => 'The user password reset'
        ],200);
    }
}