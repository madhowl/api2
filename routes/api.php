<?php

use App\Http\Controllers\API\Auth\LoginRegisterController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Public routes of authtication

Route::controller(LoginRegisterController::class)->group(
    function () {
        Route::post('/register', 'register');
        Route::post('/login', 'login');
        Route::post('/logout', 'logout');
    }
);

Route::middleware('auth:sanctum')->group(
    function () {
        Route::get(
            '/user',
            function (Request $request) {
                return $request->user();
            }
        );
        Route::post('/logout', [LoginRegisterController::class, 'logout']);
        Route::resource(
            'users',
            App\Http\Controllers\API\UserAPIController::class
        )
            ->except(['create', 'edit']);
    }
);



