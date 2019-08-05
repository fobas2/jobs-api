<?php

namespace App;

use Illuminate\Notifications\Notifiable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Passport\HasApiTokens;
use Illuminate\Database\Eloquent\SoftDeletes;
use Storage;

/**
 * Class User
 *
 * @OA\Schema(
 *     title="User model",
 *     description="Model user account",
 * )
 */

class User extends Authenticatable
{
    use Notifiable, HasApiTokens, SoftDeletes;

    /**
     * @OA\Property(
     *     property="id",
     *     type="bigIncrements",
     *     example="1"
     * ),
     * @OA\Property(
     *     property="name",
     *     type="string",
     *     example="fobas2"
     * ),
     * @OA\Property(
     *     property="email",
     *     type="string",
     *     example="azyav4ikoff@yandex.by"
     * ),
     * @OA\Property(
     *     property="avatar",
     *     type="string",
     *     example="avatar.png"
     * ),
     * @OA\Property(
     *     property="active",
     *     type="boolean",
     *     example="0"
     * ),
     * @OA\Property(
     *     property="profile",
     *     type="boolean",
     *     example="0"
     * )
     */
    protected $fillable = [
        'name', 'email', 'password', 'avatar', 'active', 'activation_token', 'profile'
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token', 'activation_token',
    ];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    protected $appends = ['avatar_url'];

    public function getAvatarUrlAttribute()
    {
        return Storage::url('avatars/'.$this->id.'/'.$this->avatar);
    }

    protected $dates = ['deleted_at'];

}
