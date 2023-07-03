<?php

namespace Gigabait\Sso\Http\Controllers;

use Illuminate\Routing\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Encryption\Encrypter;
use Pterodactyl\Models\User;

class SsoController extends Controller
{
    public function login(Request $request)
    {
        $route = '/';
        if ($request->has('token')) {

            if ($request->has('param')) {
                $param = json_decode($request->input('param'), true);
                if (isset($param['server'])) {
                    $route = "/server/{$param['server']}";
                }
            }

            $secretKey = config('sso.secret_key');
            if (strlen($secretKey) !== 32) {
                return redirect('/login')->withErrors(['sso_error' => 'Secret key length must be 32 characters.']);
            }

            $cipher = config('app.cipher');
            $encrypter = new Encrypter($secretKey, $cipher);
            $encryptedToken = $request->input('token');

            try {
                $decryptedToken = $encrypter->decrypt($encryptedToken);
            } catch (\Illuminate\Contracts\Encryption\DecryptException $e) {
                return redirect('/login')->withErrors(['sso_error' => $e->getMessage()]);;
            }

            $authMarkerData = json_decode($decryptedToken, true);
            if (hash_equals($authMarkerData['secret_key'], $secretKey)) {
                $user = User::whereEmail($authMarkerData['email'])->firstOrFail();
                if ($user) {

                    if(!$user['root_admin']) {
                        return redirect()->back()->withError('You cannot automatically login to admin accounts.');
                    }

                    if($user['2fa']) {
                        return redirect()->back()->withError('Logging into accounts with 2 Factor Authentication enabled is not supported.');
                    }
                    
                    Auth::loginUsingId($user->id);
                    return redirect()->intended($route);
                }
            }
        }
        return redirect('/login');
    }
}
