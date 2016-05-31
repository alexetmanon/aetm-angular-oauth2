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
            '$window',
            '$rootScope',
            'localStorageService',
            function (
                $q,
                $http,
                $log,
                $window,
                $rootScope,
                localStorageService
            ) {
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
                 *
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

                            throw error;
                        }
                    );
                }

                /**
                 * 1. Checks the Facebook login status
                 * 2. Manages a new login if needed
                 *
                 * @return Promise
                 */
                function handleLoginFacebook() {
                    var deferred = $q.defer();

                    // check actual login status (Facebook access)
                    facebookConnectPlugin.getLoginStatus(
                        function (response) {
                            if (response.status === 'connected' && response.authResponse && response.authResponse.accessToken) {
                                deferred.resolve(response.authResponse.accessToken);

                                return;
                            }

                            // If need ask Facebook for new connexion
                            facebookConnectPlugin.login(['email'],
                                function (response) {
                                    if (response.authResponse && response.authResponse.accessToken) {
                                        deferred.resolve(response.authResponse.accessToken);
                                    } else {
                                        deferred.reject(response);
                                    }
                                },
                                deferred.reject
                            );
                        },
                        deferred.reject
                    );

                    return deferred.promise;
                }

                /**
                 * Manages Google connect.
                 *
                 * @return Promise
                 */
                function handleLoginGoogle() {
                    var deferred = $q.defer();

                    $window.plugins.googleplus.login({
                            'scopes': 'profile email',
                            'webClientId': GOOGLE_APP_ID,
                            'offline': true
                        },
                        function (response) {
                            if (response.idToken) {
                                deferred.resolve(response.idToken);
                            } else {
                                deferred.reject(response);
                            }
                        },
                        deferred.reject
                    );

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

                            throw error;
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

                            throw error;
                        }
                    );
                }

                /**
                 * @param Object credentials
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

                            throw error;
                        }
                    );
                }

                /**
                 * Request access token from Facebook and performs API request.
                 *
                 * @return Promise
                 */
                auth.loginFacebook = function () {
                    var promise;

                    $rootScope.$broadcast('aetm-oauth2:login:start');

                    promise = handleLoginFacebook().then(function (accessToken) {
                        return connectFromFacebook(accessToken);
                    });

                    promise.finally(function () {
                        $rootScope.$broadcast('aetm-oauth2:login:end');
                    });

                    return promise;
                };

                /**
                 * Request access token from Google+ and performs API request.
                 *
                 * @return Promise
                 */
                auth.loginGoogle = function () {
                    var promise;

                    $rootScope.$broadcast('aetm-oauth2:login:start');

                    promise = handleLoginGoogle().then(function (idToken) {
                        return connectFromGoogle(idToken);
                    });

                    promise.finally(function () {
                        $rootScope.$broadcast('aetm-oauth2:login:end');
                    });

                    return promise;
                };

                /**
                 * Request access token directly to the API using `credentials`.
                 *
                 * @return Promise
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

                /**
                 * @return Boolean
                 */
                auth.isConnected = function () {
                    return !!auth.accessToken;
                };

                /**
                 * @return Object
                 */
                auth.getType = function () {
                    return auth.type;
                };

                /**
                 * @return Boolean
                 */
                auth.hasLoginStored = function () {
                    var storedLogin = localStorageService.get(STORAGE_KEY);

                    return storedLogin && storedLogin.oauthResponse && storedLogin.oauthResponse.access_token;
                };

                /**
                 * Checks if credentials are stored or if last connexion was by social connect and try to connect.
                 *
                 * @return Promise
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

                /**
                 * Updates request `Authorization` header with the one stored in `$http.defaults.headers.common.Authorization`.
                 *
                 * @param  Object config
                 * @return Object
                 */
                auth.updateRequest = function (config) {
                    // updates the buffered requests headers
                    config.headers.Authorization = $http.defaults.headers.common.Authorization;

                    return config;
                };

                return auth;
            }
        ];
    }]);
}());