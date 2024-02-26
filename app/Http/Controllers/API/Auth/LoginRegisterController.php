<?php

namespace App\Http\Controllers\API\Auth;

use App\Http\Controllers\AppBaseController;
use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Validator;

class LoginRegisterController extends AppBaseController
{
    /**
     * @OA\Post(
     *     path="/register",
     *     tags={"Auth"},
     *     summary="Registrate",
     *     operationId="Register",
     *
     *     @OA\Response(
     *         response=405,
     *         description="Invalid input"
     *     ),
     *     @OA\RequestBody(
     *         description="Input data format",
     *         @OA\MediaType(
     *             mediaType="application/x-www-form-urlencoded",
     *             @OA\Schema(
     *                 type="object",
     *                 @OA\Property(
     *                     property="name",
     *                     description="Enter your name",
     *                     type="string",
     *                 ),
     *                 @OA\Property(
     *                     property="email",
     *                     description="Enter your Email",
     *                     type="email"
     *                 ),
     *                 @OA\Property(
     *                     property="password",
     *                     description="Enter your password",
     *                     type="password"
     *                 ),
     *                 @OA\Property(
     *                     property="password_confirmation",
     *                     description="Enter your password confirmation",
     *                     type="password"
     *                 )
     *             )
     *         )
     *     )
     * )
     */
    public function register(Request $request)
    {
        $validate = Validator::make(
            $request->all(),
            [
                'name'     => 'required|string|max:250',
                'email'    => 'required|string|email:rfc,dns|max:250|unique:users,email',
                'password' => 'required|string|min:8|confirmed',
            ]
        );

        if ($validate->fails()) {
            return response()->json(
                [
                    'status'  => 'failed',
                    'message' => 'Validation Error!',
                    'data'    => $validate->errors(),
                ],
                403
            );
        }

        $user = User::create(
            [
                'name'     => $request->name,
                'email'    => $request->email,
                'password' => Hash::make($request->password),
            ]
        );

        $data['token'] = $user->createToken($request->email)->plainTextToken;
        $data['user'] = $user;

        $response = [
            'status'  => 'success',
            'message' => 'User is created successfully.',
            'data'    => $data,
        ];

        return response()->json($response, 201);
    }

    /**
     * @OA\Post(
     *     path="/login",
     *     tags={"Auth"},
     *     summary="Authentificate",
     *     operationId="Login",
     *
     *     @OA\Response(
     *         response=405,
     *         description="Invalid input"
     *     ),
     *     @OA\RequestBody(
     *         description="Input data format",
     *         @OA\MediaType(
     *             mediaType="application/x-www-form-urlencoded",
     *             @OA\Schema(
     *                 type="object",
     *                 @OA\Property(
     *                     property="email",
     *                     description="Enter your email",
     *                     type="string",
     *                 ),
     *                 @OA\Property(
     *                     property="password",
     *                     description="Enter password",
     *                     type="password"
     *                 )
     *             )
     *         )
     *     )
     * )
     */
    public function login(Request $request)
    {
        $validate = Validator::make(
            $request->all(),
            [
                'email'    => 'required|string|email',
                'password' => 'required|string',
            ]
        );

        if ($validate->fails()) {
            return response()->json(
                [
                    'status'  => 'failed',
                    'message' => 'Validation Error!',
                    'data'    => $validate->errors(),
                ],
                403
            );
        }

        // Check email exist
        $user = User::where('email', $request->email)->first();

        // Check password
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(
                [
                    'status'  => 'failed',
                    'message' => 'Invalid credentials',
                ],
                401
            );
        }

        $data['token'] = $user->createToken($request->email)->plainTextToken;
        $data['user'] = $user;

        $response = [
            'status'  => 'success',
            'message' => 'User is logged in successfully.',
            'data'    => $data,
        ];

        return response()->json($response, 200);
    }

    /**
     * @OA\Post(
     *     path="/logout",
     *     tags={"Auth"},
     *     summary="Logout user",
     *     description="Logout current user",
     *     security={{"sanctum":{}}},
     *     operationId="logout_current_user",
     *     @OA\Response(
     *         response=200,
     *         description="Everything OK",
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Something went wrong",
     *     )
     * )
     */
    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();

        return response()->json(
            [
                'status'  => 'success',
                'message' => 'User is logged out successfully',
            ],
            200
        );
    }
}
