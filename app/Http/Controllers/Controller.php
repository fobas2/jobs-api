<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;

class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    /**
     * @OA\Info(
     *     title="Jobs-API Documentation",
     *     version="0.0.4",
     *     @OA\Contact(
     *         email="azyav4ikoff@ynadex.by"
     *     )
     * )
     * @OA\Tag(
     *     name="Auth",
     *     description="Some example pages",
     * )
     * @OA\Server(
     *     description="Laravel Swagger API server",
     *     url="http://localhost:8000/api"
     * )
     * @OA\SecurityScheme(
     *      securityScheme="bearerAuth",
     *      in="header",
     *      name="bearerAuth",
     *      type="http",
     *      scheme="bearer",
     *      bearerFormat="JWT",
     * )
     */
}
