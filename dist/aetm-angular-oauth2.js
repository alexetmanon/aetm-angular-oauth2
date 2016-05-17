(function () {
    'use strict';

    angular
    .module('aetm-oauth2', [
        'LocalStorageModule'
    ])
    .config(['localStorageServiceProvider', function (localStorageServiceProvider) {
        /**
         * Dependencies configs
         */
        localStorageServiceProvider.setPrefix('aetm');
    }])
    .provider('aetmOAuth2Service', [function () {
        var self = this;

        /**
         * Local configs
         */
        self.apiBase = "";
        self.apiClientId = "";
        self.apiClientSecret = "";
        self.googleAppId = "";

        /**
         * @param  Object options
         */
        self.configure = function (options) {
            self.apiBase = options.apiBase || "";
            self.apiClientId = options.apiClientId || "";
            self.apiClientSecret = options.apiClientSecret || "";
            self.googleAppId = options.googleAppId || "";
        };

        /**
         * Service
         */
        this.$get = [
            '$q',
            '$http',
            '$log',
            'localStorageService',
            '$window',
            '$rootScope',
            function ($q, $http, $log, localStorageService, $window, $rootScope) {
                var API_BASE = self.apiBase,
                    API_CLIENT_ID = self.apiClientId,
                    API_CLIENT_SECRET = self.apiClientSecret,
                    GOOGLE_APP_ID = self.googleAppId,
                    STORAGE_KEY = 'aetmAuthStorage';

                var auth = {
                    accessToken: null,
                    type: null
                };

                /**
                 * Init access toke from API response
                 */
                function initData(response, type) {
                    auth.accessToken = response.access_token;
                    auth.type = type;

                    // add token to all request
                    $http.defaults.headers.common.Authorization = 'Bearer ' + auth.accessToken;

                    // remenbers login
                    rememberLogin(type, response);
                }

                /**
                 * @param  String type
                 * @param  Object credentials
                 */
                function rememberLogin(type, oauthResponse) {
                    localStorageService.set(STORAGE_KEY, {
                        type: type,
                        oauthResponse: oauthResponse
                    });
                }

                function forgetLogin() {
                    localStorageService.remove(STORAGE_KEY);
                }

                /**
                 * Get new accessToken from given refreshToken
                 * @param  String refreshToken
                 * @return Promise
                 */
                function refreshAccess(refreshToken, type) {
                    $rootScope.$broadcast('aetm-oauth2:login:start');

                    return $http.post(API_BASE + '/oauth/v2/token', {
                        "grant_type": "refresh_token",
                        "client_id": API_CLIENT_ID,
                        "client_secret": API_CLIENT_SECRET,
                        "refresh_token": refreshToken
                    }).then(
                        function (response) {
                            // Store needed data
                            initData(response.data, type);

                            $rootScope.$broadcast('aetm-oauth2:login:end');

                            return response;
                        },
                        function (error) {
                            $log.error('API connection error', error);

                            $rootScope.$broadcast('aetm-oauth2:login:end');

                            return error;
                        }
                    );
                }

                /**
                 *
                 */
                function checkLoginStatusFacebook() {
                    var deferred = $q.defer();

                    $rootScope.$broadcast('aetm-oauth2:login:start');

                    facebookConnectPlugin.getLoginStatus(
                        function (response) {
                            if (response.status === 'connected') {
                                connectFromFacebook(response.authResponse.accessToken)
                                    .then(function (data) {
                                        deferred.resolve(data);
                                    }, function (error) {
                                        deferred.reject(error);
                                    });
                            } else {
                                deferred.resolve(response);
                            }
                        },
                        function (error) {
                            deferred.reject(error);
                        }
                    );

                    deferred.promise.finally(function () {
                        $rootScope.$broadcast('aetm-oauth2:login:end');
                    });

                    return deferred.promise;
                }

                /**
                 * @param Object facebookResponse
                 */
                function connectFromFacebook(accessToken) {
                    return $http.post(API_BASE + '/oauth/v2/token', {
                        "grant_type": "http://platform.local/grants/facebook_access_token",
                        "client_id": API_CLIENT_ID,
                        "client_secret": API_CLIENT_SECRET,
                        "accessToken": accessToken
                    }).then(
                        function (response) {
                            // Store needed data
                            initData(response.data, 'facebook');

                            return response;
                        },
                        function (error) {
                            $log.error('API connection error', error);

                            return error;
                        }
                    );
                }

                /**
                 * @param Object googleResponse
                 */
                function connectFromGoogle(idToken) {
                    return $http.post(API_BASE + '/oauth/v2/token', {
                        "grant_type": "http://platform.local/grants/google_access_token",
                        "client_id": API_CLIENT_ID,
                        "client_secret": API_CLIENT_SECRET,
                        "accessToken": idToken
                    }).then(
                        function (response) {
                            // Store needed data
                            initData(response.data, 'google');

                            return response;
                        },
                        function (error) {
                            $log.error('API connection error', error);

                            return error;
                        }
                    );
                }

                /**
                 * @param  Object credentials
                 */
                function connectFromEmail(credentials) {
                    if (!credentials || !credentials.email || !credentials.password) {
                        return $q.reject('Missing credentials. "email" and "password" required.');
                    }

                    return $http.post(API_BASE + '/oauth/v2/token', {
                        "grant_type": "password",
                        "client_id": API_CLIENT_ID,
                        "client_secret": API_CLIENT_SECRET,
                        "username": credentials.email,
                        "password": credentials.password
                    }).then(
                        function (response) {
                            // Store needed data
                            initData(response.data, 'email');

                            return response;
                        },
                        function (error) {
                            $log.error('API connection error', error);

                            return error;
                        }
                    );
                }

                /**
                 * Request access token from fbconnect and perform API request
                 */
                auth.loginFacebook = function () {
                    var deferred = $q.defer();

                    $rootScope.$broadcast('aetm-oauth2:login:start');

                    facebookConnectPlugin.login(['email'],
                        function (response) {
                            if (response.authResponse && response.authResponse.accessToken) {
                                connectFromFacebook(response.authResponse.accessToken)
                                    .then(function (data) {
                                        deferred.resolve(data);
                                    }, function (error) {
                                        deferred.reject(error);
                                    });
                            } else {
                                deferred.reject(response);
                            }
                        },
                        function (error) {
                            deferred.reject(error);
                        });

                    deferred.promise.finally(function () {
                        $rootScope.$broadcast('aetm-oauth2:login:end');
                    });

                    return deferred.promise;
                };

                /**
                 * Request access token from Google+ connect and perform API request
                 */
                auth.loginGoogle = function () {
                    var deferred = $q.defer();

                    $rootScope.$broadcast('aetm-oauth2:login:start');

                    $window.plugins.googleplus.login({
                            'scopes': 'profile email',
                            'webClientId': GOOGLE_APP_ID,
                            'offline': true
                        },
                        function (response) {
                            if (response.idToken) {
                                connectFromGoogle(response.idToken)
                                    .then(function (data) {
                                        deferred.resolve(data);
                                    }, function (error) {
                                        deferred.reject(error);
                                    });
                            } else {
                                deferred.reject(response);
                            }
                        },
                        function (error) {
                            deferred.reject(error);
                        });

                    deferred.promise.finally(function () {
                        $rootScope.$broadcast('aetm-oauth2:login:end');
                    });

                    return deferred.promise;
                };

                /**
                 * Request access token directly to the API using `credentials`
                 */
                auth.loginEmail = function (credentials) {
                    var promise;

                    $rootScope.$broadcast('aetm-oauth2:login:start');

                    promise = connectFromEmail(credentials);

                    promise.finally(function () {
                        $rootScope.$broadcast('aetm-oauth2:login:end');
                    });

                    return promise;
                };

                auth.isConnected = function () {
                    return !!auth.accessToken;
                };

                auth.getType = function () {
                    return auth.type;
                };

                /**
                 * Checks if credentials are stored or if last connexion was by social connect and try to connect.
                 */
                auth.checkLoginStatus = function () {
                    var storedLogin = localStorageService.get(STORAGE_KEY);

                    if (storedLogin && storedLogin.oauthResponse && storedLogin.oauthResponse.access_token) {

                        // refresh access token using stored refresk token and returns a connection status
                        return refreshAccess(storedLogin.oauthResponse.refresh_token, storedLogin.type).then(function (response) {
                            if (response.data && response.data.access_token) {
                                return {
                                    status: 'connected'
                                };
                            } else {
                                return {
                                    status: 'unknown'
                                };
                            }
                        });
                    }

                    return $q.resolve({
                        status: 'disconnected'
                    });
                };

                /**
                 * Logout from API and removes stored tokens.
                 */
                auth.logout = function () {
                    auth = {};

                    // removes default token
                    delete $http.defaults.headers.common.Authorization;

                    forgetLogin();
                };

                return auth;
            }
        ];
    }]);
}());