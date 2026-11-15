(function () {
    'use strict';

    var KEY = 'stalwart-ui';
    var root = document.documentElement;
    var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

    var LOGO = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 450 81" role="img" aria-label="Abnormal Mail">'
        + '<text x="225" y="55" text-anchor="middle" font-family="system-ui, sans-serif" font-size="46" font-weight="600" fill="currentColor">Abnormal Mail</text>'
        + '</svg>';

    function readStore() {
        try {
            var stored = JSON.parse(window.localStorage.getItem(KEY));
            return stored && typeof stored === 'object' ? stored : null;
        } catch (e) {
            return null;
        }
    }

    function storedTheme() {
        var stored = readStore();
        var theme = stored && stored.state && stored.state.theme;
        return theme === 'dark' || theme === 'light' ? theme : null;
    }

    function applyTheme(theme) {
        root.classList.toggle('dark', theme === 'dark');
        root.classList.toggle('light', theme === 'light');
    }

    function currentTheme() {
        if (root.classList.contains('dark')) return 'dark';
        if (root.classList.contains('light')) return 'light';
        return media && media.matches ? 'dark' : 'light';
    }

    function setTheme(theme) {
        applyTheme(theme);
        var stored = readStore() || { state: {}, version: 0 };
        if (!stored.state || typeof stored.state !== 'object') stored.state = {};
        stored.state.theme = theme;
        try {
            window.localStorage.setItem(KEY, JSON.stringify(stored));
        } catch (e) {
            return;
        }
    }

    function labelToggle(button) {
        button.setAttribute('aria-label', currentTheme() === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    }

    applyTheme(storedTheme());

    var $ = function (id) { return document.getElementById(id); };

    function setText(el, text) { if (el) el.textContent = text == null ? '' : String(text); }
    function show(el) { if (el) el.hidden = false; }
    function hide(el) { if (el) el.hidden = true; }
    function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

    function loadLogo(wrap, target, credentials) {
        function showDefault() { wrap.innerHTML = LOGO; }
        fetch(target, { method: 'GET', credentials: credentials })
            .then(function (res) {
                if (!res.ok) return null;
                var ct = (res.headers.get('content-type') || '').toLowerCase();
                return ct.indexOf('image/') === 0 ? res.blob() : null;
            })
            .then(function (blob) {
                if (!blob) { showDefault(); return; }
                var objectUrl = URL.createObjectURL(blob);
                var img = new Image();
                img.alt = 'Logo';
                img.onload = function () { clear(wrap); wrap.appendChild(img); };
                img.onerror = function () { URL.revokeObjectURL(objectUrl); showDefault(); };
                img.src = objectUrl;
            })
            .catch(function () { showDefault(); });
    }

    function loginPage() {
            var FAILURE = 'Temporary server failure. If the problem persists, contact your administrator.';

            function showError(msg) {
                var a = $('alert');
                a.classList.remove('success');
                setText($('alert-msg'), msg);
                show(a);
            }

            function showSuccess(msg) {
                var a = $('alert');
                a.classList.add('success');
                setText($('alert-msg'), msg);
                show(a);
            }

            function clearAlert() { hide($('alert')); }

            var url = new URL(window.location.href);
            var params = url.searchParams;
            var isDevice = /\/device(\/|$)/.test(url.pathname);
            var query = url.search.charAt(0) === '?' ? url.search.slice(1) : url.search;
            var loginHint = params.get('login_hint');
            var clientInfo = null;
            var deviceCode = null;
            var stage = 'login';
            var inMfa = false;
            var lastCreds = null;
            var allowHandler = null;
            var denyHandler = null;
            var leaving = false;
            var passkeySupported = !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.get);
            var passkeyAbort = null;
            var passkeyTimer = null;
            var passkeyRetries = 0;
            var passkeyBusy = false;
            var lastPasskey = null;
            var PASSKEY_RENEW_MS = 30000;
            var PASSKEY_RETRY_MS = 5000;
            var PASSKEY_MAX_RETRIES = 3;

            if (loginHint) $('username').value = loginHint;

            var BLOCKED_PROTOCOLS = ['javascript:', 'data:', 'vbscript:', 'file:', 'blob:', 'about:'];

            function isSafeLocation(location) {
                try {
                    return BLOCKED_PROTOCOLS.indexOf(new URL(location).protocol.toLowerCase()) === -1;
                } catch (e) {
                    return false;
                }
            }

            function navigate(location) {
                if (typeof location !== 'string' || !location) {
                    showFatal(FAILURE);
                } else if (!isSafeLocation(location)) {
                    showFatal('The application redirect address is not allowed.');
                } else {
                    leaving = true;
                    cancelAutofill();
                    window.location.assign(location);
                }
            }

            function showFatal(msg) {
                stage = 'done';
                cancelAutofill();
                hide($('login-form'));
                hide($('consent'));
                hide($('app-tile'));
                setText($('title'), 'Unable to continue');
                setText($('subtitle'), '');
                showError(msg);
            }

            function hashHue(seed) {
                var h = 0;
                for (var i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
                return h % 360;
            }

            function isSafeLogo(logo) {
                if (typeof logo !== 'string' || !logo) return false;
                if (logo.indexOf('data:image/') === 0) return true;
                try {
                    return new URL(logo, window.location.href).origin === window.location.origin;
                } catch (e) {
                    return false;
                }
            }

            function renderTile(tile, name, logo, seed) {
                clear(tile);
                tile.style.background = '';
                if (isSafeLogo(logo)) {
                    var img = new Image();
                    img.alt = '';
                    img.onerror = function () { renderTile(tile, name, null, seed); };
                    img.src = logo;
                    tile.appendChild(img);
                    return;
                }
                var letter = Array.from((name || '').trim())[0] || '?';
                tile.style.background = 'hsl(' + hashHue(seed || name || '') + ',45%,45%)';
                setText(tile, letter.toUpperCase());
            }

            function renderConsent(info, onAllow, onDeny) {
                var name = typeof info.name === 'string' && info.name ? info.name : 'Unnamed application';
                setText($('client-name'), name);
                if (info.verified) hide($('client-unverified')); else show($('client-unverified'));
                if (typeof info.clientHost === 'string' && info.clientHost) {
                    setText($('client-host'), info.clientHost);
                    show($('client-host'));
                } else {
                    hide($('client-host'));
                }
                renderTile($('client-tile'), name, info.verified ? info.logo : null,
                    info.clientHost || info.redirectHost || name);

                var list = $('client-scopes');
                clear(list);
                var scopes = Array.isArray(info.scopes) ? info.scopes : [];
                if (!scopes.length) scopes = ['Confirm that you have an account on this server'];
                scopes.forEach(function (label) {
                    var li = document.createElement('li');
                    setText(li, label);
                    list.appendChild(li);
                });

                if (typeof info.redirectHost === 'string' && info.redirectHost) {
                    setText($('client-redirect'), 'You will be sent back to ' + info.redirectHost + ' after you sign in.');
                    show($('client-redirect'));
                } else {
                    hide($('client-redirect'));
                }

                cancelAutofill();
                hide($('login-form'));
                hide($('app-tile'));
                setText($('title'), isDevice ? 'Authorize device' : 'Authorize access');
                setText($('subtitle'), isDevice
                    ? 'A device is requesting access to your account.'
                    : 'An application is requesting access to your account.');
                allowHandler = onAllow;
                denyHandler = onDeny;
                stage = 'consent';
                show($('consent'));
                setTimeout(function () { $('allow-btn').focus(); }, 0);
            }

            function showLoginForm() {
                stage = 'login';
                hide($('consent'));
                show($('field-username'));
                show($('field-password'));
                hide($('field-device-code'));
                hide($('field-otp'));
                setText($('submit-btn'), 'Sign in');
                var name = clientInfo && typeof clientInfo.name === 'string' ? clientInfo.name : '';
                if (clientInfo && !clientInfo.consentRequired && name) {
                    setText($('title'), 'Sign in to ' + name);
                    if (isSafeLogo(clientInfo.logo)) {
                        renderTile($('app-tile'), name, clientInfo.logo, name);
                        show($('app-tile'));
                    }
                    setText($('subtitle'), 'Enter your credentials to continue');
                } else {
                    setText($('title'), 'Sign in');
                    setText($('subtitle'), name
                        ? 'Enter your credentials to continue to ' + name
                        : 'Enter your credentials to continue');
                }
                show($('login-form'));
                if (passkeySupported) {
                    show($('passkey-btn'));
                    armAutofill();
                }
                focusFirst();
            }

            function focusFirst() {
                setTimeout(function () {
                    if (stage === 'code') { $('device-code').focus(); return; }
                    if (!$('username').value) { $('username').focus(); return; }
                    if (!$('password').value) { $('password').focus(); return; }
                }, 0);
            }

            function enterMfaMode() {
                inMfa = true;
                cancelAutofill();
                hide($('field-username'));
                hide($('field-password'));
                hide($('passkey-btn'));
                show($('field-otp'));
                setText($('title'), 'Two-factor authentication');
                setText($('subtitle'), 'Enter the 6-digit code from your authenticator app.');
                clearAlert();
                setTimeout(function () { $('otp').focus(); }, 0);
            }

            function leaveMfaMode() {
                inMfa = false;
                $('otp').value = '';
                showLoginForm();
            }

            (function loadCustomLogo() {
                var target = '/logo';
                if (loginHint) {
                    var at = loginHint.lastIndexOf('@');
                    if (at !== -1 && at < loginHint.length - 1) {
                        target = '/logo?domain=' + encodeURIComponent(loginHint.slice(at + 1).toLowerCase());
                    }
                }
                loadLogo($('logo-wrap'), target, 'same-origin');
            })();

            function getJson(target) {
                return fetch(target, {
                    method: 'GET',
                    credentials: 'same-origin',
                    cache: 'no-store',
                    headers: { 'Accept': 'application/json' }
                }).then(function (res) {
                    if (res.status !== 200) throw new Error('http ' + res.status);
                    return res.json();
                });
            }

            function postAuth(body) {
                return fetch('/api/auth', {
                    method: 'POST',
                    credentials: 'same-origin',
                    cache: 'no-store',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify(body)
                }).then(function (res) {
                    if (res.status !== 200) {
                        return res.text().then(function (txt) {
                            console.log('Login endpoint returned HTTP', res.status, txt);
                            throw new Error('http ' + res.status);
                        });
                    }
                    return res.json();
                });
            }

            function postLogin(body) {
                var btn = $('submit-btn');
                btn.disabled = true;
                return postAuth(body).then(function (json) {
                    handleResponse(json);
                }).catch(function (err) {
                    console.log('Login request failed:', err);
                    showError(FAILURE);
                }).then(function () {
                    btn.disabled = false;
                });
            }

            function handleResponse(resp) {
                if (!resp || typeof resp !== 'object' || typeof resp.type !== 'string') {
                    console.log('Malformed login response:', resp);
                    showError(FAILURE);
                    return;
                }
                switch (resp.type) {
                    case 'authenticated':
                    case 'redirect':
                        navigate(resp.location);
                        return;
                    case 'invalid':
                        showFatal(typeof resp.description === 'string' && resp.description
                            ? resp.description
                            : 'The sign-in request is invalid.');
                        return;
                    case 'verified':
                        stage = 'done';
                        cancelAutofill();
                        hide($('login-form'));
                        hide($('consent'));
                        setText($('title'), 'Device authorized');
                        setText($('subtitle'), 'You have successfully authorized this device. You may now close this window.');
                        showSuccess('Device verified.');
                        return;
                    case 'denied':
                        stage = 'done';
                        cancelAutofill();
                        hide($('login-form'));
                        hide($('consent'));
                        setText($('title'), 'Access denied');
                        setText($('subtitle'), 'The device was not authorized. You may now close this window.');
                        clearAlert();
                        return;
                    case 'mfaRequired':
                        enterMfaMode();
                        return;
                    case 'consentRequired':
                        requestConsent(resp.token);
                        return;
                    case 'expired':
                        if (inMfa) leaveMfaMode();
                        showError('Your password has expired. Change it in the account portal, then sign in again.');
                        return;
                    case 'passkeyUnknown':
                        signalUnknownPasskey();
                        showError('This passkey is not registered with any account. It may have been removed; sign in with your password instead.');
                        return;
                    case 'failure':
                        if (inMfa) leaveMfaMode();
                        if (lastPasskey) {
                            showError(isDevice
                                ? 'Passkey sign-in failed, or the device code has expired. Please try again.'
                                : 'Passkey sign-in failed. Please try again.');
                            return;
                        }
                        showError(isDevice
                            ? 'Invalid username or password, or the device code has expired. Please try again.'
                            : 'Invalid username or password. Please try again.');
                        return;
                    default:
                        console.log('Unknown login response type:', resp);
                        showError(FAILURE);
                }
            }

            function buildRequest(creds, otpValue) {
                var r;
                if (isDevice) {
                    r = {
                        type: 'authDevice',
                        accountName: creds.account_name,
                        accountSecret: creds.account_secret,
                        code: deviceCode,
                        consent: true
                    };
                } else {
                    r = {
                        type: 'authCode',
                        accountName: creds.account_name,
                        accountSecret: creds.account_secret,
                        query: query
                    };
                }
                if (otpValue) r.mfaToken = otpValue;
                return r;
            }

            function requestConsent(token) {
                if (typeof token !== 'string' || !token || !clientInfo) {
                    showFatal(FAILURE);
                    return;
                }
                inMfa = false;
                lastCreds = null;
                $('password').value = '';
                $('otp').value = '';
                hide($('field-otp'));
                var decide = function (allow) {
                    postConsent({ type: 'authConsent', token: token, query: query, consent: allow });
                };
                renderConsent(clientInfo, function () { decide(true); }, function () { decide(false); });
            }

            function postConsent(body) {
                var allow = $('allow-btn');
                var deny = $('deny-btn');
                allow.disabled = true;
                deny.disabled = true;
                postLogin(body).then(function () {
                    if (leaving) return;
                    allow.disabled = false;
                    deny.disabled = false;
                });
            }

            function normalizeCode(value) {
                var code = (value || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
                return code.length === 8 ? code.slice(0, 4) + '-' + code.slice(4) : code;
            }

            function lookupDevice() {
                var code = normalizeCode($('device-code').value);
                if (!code) {
                    showError('Please enter the device code.');
                    return;
                }
                $('device-code').value = code;
                var btn = $('submit-btn');
                btn.disabled = true;
                getJson('/api/auth/client?user_code=' + encodeURIComponent(code)).then(function (info) {
                    if (!info || typeof info !== 'object' || typeof info.error === 'string') {
                        showError('The device code is invalid or has expired.');
                        return;
                    }
                    deviceCode = code;
                    clientInfo = info;
                    renderConsent(info, function () {
                        showLoginForm();
                    }, function () {
                        postLogin({ type: 'authDevice', code: deviceCode, consent: false });
                    });
                }).catch(function (err) {
                    console.log('Device lookup failed:', err);
                    showError(FAILURE);
                }).then(function () {
                    btn.disabled = false;
                });
            }

            function bytesToBase64Url(buffer) {
                var bytes = new Uint8Array(buffer);
                var binary = '';
                for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
                return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            }

            function base64UrlToBytes(value) {
                var base64 = value.replace(/-/g, '+').replace(/_/g, '/');
                while (base64.length % 4) base64 += '=';
                var binary = atob(base64);
                var bytes = new Uint8Array(binary.length);
                for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                return bytes;
            }

            function credentialToJson(credential) {
                if (typeof credential.toJSON === 'function') {
                    try { return credential.toJSON(); } catch (e) { }
                }
                var response = credential.response;
                return {
                    id: credential.id,
                    rawId: bytesToBase64Url(credential.rawId),
                    type: credential.type,
                    response: {
                        clientDataJSON: bytesToBase64Url(response.clientDataJSON),
                        authenticatorData: bytesToBase64Url(response.authenticatorData),
                        signature: bytesToBase64Url(response.signature),
                        userHandle: response.userHandle ? bytesToBase64Url(response.userHandle) : null
                    }
                };
            }

            function isPasskeyCancel(err) {
                return !!err && (err.name === 'NotAllowedError' || err.name === 'AbortError');
            }

            function fetchPasskeyOptions() {
                return postAuth({ type: 'passkeyOptions' }).then(function (options) {
                    if (!options || options.type !== 'passkeyOptions' || typeof options.challenge !== 'string') {
                        throw new Error('passkey options unavailable');
                    }
                    return options;
                });
            }

            function getPasskey(options, mediation, signal) {
                var request = {
                    publicKey: {
                        challenge: base64UrlToBytes(options.challenge),
                        rpId: options.rpId,
                        timeout: options.timeout,
                        userVerification: 'required',
                        allowCredentials: []
                    }
                };
                if (mediation) request.mediation = mediation;
                if (signal) request.signal = signal;
                return navigator.credentials.get(request).then(function (credential) {
                    if (!credential) throw new Error('no credential returned');
                    return { credential: credential, rpId: options.rpId };
                });
            }

            function submitPasskey(result) {
                var credential = credentialToJson(result.credential);
                lastPasskey = { rpId: result.rpId, id: result.credential.id };
                return postLogin(isDevice
                    ? { type: 'authDevicePasskey', credential: credential, code: deviceCode, consent: true }
                    : { type: 'authCodePasskey', credential: credential, query: query });
            }

            function signalUnknownPasskey() {
                if (lastPasskey && window.PublicKeyCredential && typeof PublicKeyCredential.signalUnknownCredential === 'function') {
                    PublicKeyCredential.signalUnknownCredential({ rpId: lastPasskey.rpId, credentialId: lastPasskey.id })
                        .catch(function () { });
                }
            }

            function cancelAutofill() {
                if (passkeyTimer) {
                    clearTimeout(passkeyTimer);
                    passkeyTimer = null;
                }
                if (passkeyAbort) {
                    var controller = passkeyAbort;
                    passkeyAbort = null;
                    controller.abort();
                }
            }

            function armAutofill() {
                if (!passkeySupported || typeof PublicKeyCredential.isConditionalMediationAvailable !== 'function') return;
                PublicKeyCredential.isConditionalMediationAvailable().then(function (available) {
                    if (available) startAutofill();
                }).catch(function () { });
            }

            function startAutofill() {
                cancelAutofill();
                if (stage !== 'login' || inMfa || leaving || passkeyBusy || typeof AbortController !== 'function') return;
                var controller = new AbortController();
                passkeyAbort = controller;
                var isCurrent = function () { return passkeyAbort === controller; };
                fetchPasskeyOptions().then(function (options) {
                    if (!isCurrent()) return false;
                    passkeyTimer = setTimeout(startAutofill, Math.max(options.timeout - PASSKEY_RENEW_MS, PASSKEY_RETRY_MS));
                    return getPasskey(options, 'conditional', controller.signal).then(function (result) {
                        if (!isCurrent()) return false;
                        cancelAutofill();
                        passkeyRetries = 0;
                        clearAlert();
                        return submitPasskey(result).then(function () { return true; });
                    });
                }).catch(function (err) {
                    if (!isCurrent()) return false;
                    cancelAutofill();
                    if (!isPasskeyCancel(err)) console.log('Passkey autofill failed:', err);
                    if (passkeyRetries++ < PASSKEY_MAX_RETRIES) passkeyTimer = setTimeout(startAutofill, PASSKEY_RETRY_MS);
                    return false;
                }).then(function (submitted) {
                    if (submitted) armAutofill();
                });
            }

            function setPasskeyBusy(busy) {
                passkeyBusy = busy;
                $('passkey-btn').disabled = busy;
                $('submit-btn').disabled = busy;
                if (busy) {
                    hide($('passkey-icon'));
                    show($('passkey-spinner'));
                    setText($('passkey-label'), 'Waiting for your passkey');
                } else {
                    show($('passkey-icon'));
                    hide($('passkey-spinner'));
                    setText($('passkey-label'), 'Sign in with a passkey');
                }
            }

            function signInWithPasskey() {
                if (stage !== 'login' || inMfa) return;
                clearAlert();
                cancelAutofill();
                setPasskeyBusy(true);
                fetchPasskeyOptions().then(function (options) {
                    return getPasskey(options, null, null);
                }).then(function (result) {
                    return submitPasskey(result);
                }).catch(function (err) {
                    if (isPasskeyCancel(err)) return;
                    console.log('Passkey sign-in failed:', err);
                    showError('Passkey sign-in failed. Please try again or sign in with your password.');
                }).then(function () {
                    if (leaving) return;
                    setPasskeyBusy(false);
                    if (stage === 'login' && !inMfa) armAutofill();
                });
            }

            function startDevice() {
                stage = 'code';
                hide($('passkey-btn'));
                hide($('field-username'));
                hide($('field-password'));
                show($('field-device-code'));
                setText($('submit-btn'), 'Continue');
                setText($('title'), 'Authorize device');
                setText($('subtitle'), 'Enter the code shown on your device.');
                var prefillCode = params.get('code');
                if (prefillCode) {
                    $('device-code').value = normalizeCode(prefillCode);
                    lookupDevice();
                } else {
                    focusFirst();
                }
            }

            function startAuthorization() {
                hide($('login-form'));
                if (!query) {
                    setText($('title'), 'Sign in with an app');
                    setText($('subtitle'), 'This page is opened automatically by your mail, calendar or contacts app to authorize access to your account.');
                    showError('This sign-in page cannot be used directly. Please start the sign-in from your app instead.');
                    return;
                }
                setText($('subtitle'), 'Loading...');
                getJson('/api/auth/client?' + query).then(function (info) {
                    if (!info || typeof info !== 'object') throw new Error('malformed response');
                    if (typeof info.error === 'string') {
                        if (info.redirect === true) {
                            navigate(info.location);
                        } else {
                            showFatal(typeof info.description === 'string' && info.description
                                ? info.description
                                : 'The sign-in request is invalid.');
                        }
                        return;
                    }
                    clientInfo = info;
                    showLoginForm();
                }).catch(function (err) {
                    console.log('Client lookup failed:', err);
                    showFatal(FAILURE);
                });
            }

            function submitLogin(e) {
                if (e) e.preventDefault();
                clearAlert();

                if (stage === 'code') {
                    lookupDevice();
                    return;
                } else if (stage !== 'login') {
                    return;
                }

                if (inMfa) {
                    var otp = ($('otp').value || '').trim();
                    if (!otp) { showError('Please enter your one-time code.'); return; }
                    if (!lastCreds) {
                        leaveMfaMode();
                        showError('Session expired. Please sign in again.');
                        return;
                    }
                    postLogin(buildRequest(lastCreds, otp));
                    return;
                }

                var username = ($('username').value || '').trim();
                var password = $('password').value || '';
                if (!username || !password) {
                    showError('Please enter your username and password.');
                    return;
                }
                cancelAutofill();
                lastPasskey = null;
                lastCreds = { account_name: username, account_secret: password };
                postLogin(buildRequest(lastCreds, null)).then(armAutofill);
            }

            $('login-form').addEventListener('submit', submitLogin);
            $('passkey-btn').addEventListener('click', signInWithPasskey);
            $('allow-btn').addEventListener('click', function () {
                clearAlert();
                if (allowHandler) allowHandler();
            });
            $('deny-btn').addEventListener('click', function () {
                clearAlert();
                if (denyHandler) denyHandler();
            });

            $('otp').addEventListener('input', function () {
                this.value = this.value.replace(/\D/g, '');
                if (this.value.length === 6) submitLogin();
            });

            if (isDevice) startDevice(); else startAuthorization();
    }

    function rsvpPage() {
            var FALLBACK = {
                invitation: 'Invitation',
                updatedInvitation: 'Updated invitation',
                cancelled: 'Cancelled',
                description: 'Description',
                attendees: 'Attendees',
                organizer: 'Organizer',
                location: 'Location',
                conference: 'Conference',
                when: 'When',
                you: 'you',
                yes: 'Yes',
                maybe: 'Maybe',
                no: 'No',
                replyAs: 'Reply as $name',
                note: 'Note to the organizer (optional)',
                noteHint: 'Add a short message for the organizer.',
                send: 'Send response',
                update: 'Update response',
                change: 'Change my response',
                recorded: 'Your RSVP has been recorded',
                notified: 'The organizer has been notified.',
                accepted: 'Accepted',
                tentative: 'Tentative',
                declined: 'Declined',
                showMore: 'Show more',
                showLess: 'Show less',
                failed: 'RSVP failed',
                invalidLink: 'This RSVP link is not valid.',
                error: 'Temporary server failure. If the problem persists, contact your administrator.'
            };

            var PARTSTATS = ['accepted', 'tentative', 'declined'];
            function isPartStat(value) {
                return PARTSTATS.indexOf(value) !== -1;
            }

            var labels = FALLBACK;
            function applyDirection(resp) {
                if (!resp || !resp.language) return;
                var root = document.documentElement;
                root.lang = resp.language;
                root.dir = resp.dir === 'rtl' ? 'rtl' : 'ltr';
            }

            function t(key, name) {
                var value = (labels && labels[key]) || FALLBACK[key] || key;
                if (name != null) value = value.replace('$name', name);
                return value;
            }

            var url = new URL(window.location.href);
            var token = url.searchParams.get('i') || '';
            var preset = (url.searchParams.get('m') || '').toLowerCase();
            var apiUrl = (function () {
                var path = url.pathname.replace(/\/+$/, '');
                var at = path.lastIndexOf('/calendar/rsvp');
                return (at >= 0 ? path.slice(0, at) : '') + '/api/calendar/rsvp';
            })();

            function post(body) {
                return fetch(apiUrl, {
                    method: 'POST',
                    credentials: 'omit',
                    cache: 'no-store',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                }).then(function (res) {
                    return res.json().catch(function () {
                        return { type: 'error', reason: 'serverError' };
                    });
                });
            }

            var data = null;
            var selected = '';
            var peopleExpanded = false;
            var inFlight = false;

            function clearAlert() { hide($('alert')); }
            function showAlert(msg) { setText($('alert-msg'), msg); show($('alert')); }

            function fail(title, message) {
                hide($('view-loading'));
                hide($('view-event'));
                title = title || t('failed');
                document.title = title;
                setText($('error-title'), title);
                setText($('error-detail'), message || t('error'));
                show($('view-error'));
                $('error-title').focus();
            }

            function renderPeople() {
                var list = (data.attendees || []);
                var box = $('people');
                clear(box);
                if (!list.length) { hide($('section-people')); return; }

                var limit = peopleExpanded ? list.length : Math.min(list.length, 5);
                for (var i = 0; i < limit; i++) {
                    var person = list[i];
                    var row = document.createElement('div');
                    row.className = 'person';

                    var dot = document.createElement('span');
                    dot.className = 'dot ' + String(person.partstat || '').toLowerCase();
                    row.appendChild(dot);

                    var who = document.createElement('span');
                    who.className = 'who';
                    setText(who, person.name || person.email);
                    row.appendChild(who);

                    if (person.isOrganizer) {
                        var tagOrg = document.createElement('span');
                        tagOrg.className = 'chip';
                        setText(tagOrg, t('organizer'));
                        row.appendChild(tagOrg);
                    }
                    if (data.attendee && person.email &&
                        person.email.toLowerCase() === String(data.attendee.email || '').toLowerCase()) {
                        var tagYou = document.createElement('span');
                        tagYou.className = 'chip';
                        setText(tagYou, t('you'));
                        row.appendChild(tagYou);
                    }
                    box.appendChild(row);
                }

                var toggle = $('people-toggle');
                if (list.length > 5) {
                    setText(toggle, peopleExpanded ? t('showLess') : t('showMore'));
                    show(toggle);
                } else {
                    hide(toggle);
                }
                show($('section-people'));
            }

            function select(value) {
                if (inFlight || !isPartStat(value)) return;
                selected = value;
                var nodes = $('choices').querySelectorAll('.choice');
                for (var i = 0; i < nodes.length; i++) {
                    var checked = nodes[i].getAttribute('data-value') === value;
                    nodes[i].setAttribute('aria-checked', checked ? 'true' : 'false');
                    nodes[i].tabIndex = checked ? 0 : -1;
                }
                show($('note-wrap'));
                $('send').disabled = !value;
                clearAlert();
            }

            function renderRecorded(partstat) {
                var badge = $('recorded-badge');
                badge.className = 'badge' + (partstat === 'accepted' ? '' : ' ' + partstat);
                setText($('recorded-title'), t('recorded'));
                setText($('recorded-detail'), t(partstat) + '. ' + t('notified'));
                setText($('change'), t('change'));
                hide($('respond'));
                show($('recorded'));
                $('recorded-title').focus();
            }

            function renderEvent() {
                labels = data.labels || FALLBACK;

                var kind = data.kind || 'invitation';
                var kindEl = $('kind');
                setText(kindEl, kind === 'update' ? t('updatedInvitation')
                    : kind === 'cancel' ? t('cancelled') : t('invitation'));
                if (kind === 'cancel') kindEl.className = 'eyebrow danger';

                setText($('summary'), data.summary || t('invitation'));
                document.title = data.summary || t('invitation');

                var organizer = findOrganizer(data);
                if (organizer) {
                    setText($('byline'), t('organizer') + ': '
                        + (organizer.name || organizer.email));
                    show($('byline'));
                }

                if (data.when) {
                    setText($('when'), data.when);
                    show($('row-when'));
                }
                if (data.recurrence) { setText($('repeat'), data.recurrence); show($('row-repeat')); }
                if (data.location) { setText($('where'), data.location); show($('row-where')); }
                if (data.conference) {
                    var link = $('conference');
                    setText(link, data.conference.value);
                    if (data.conference.url) {
                        link.href = data.conference.url;
                    } else {
                        link.removeAttribute('href');
                    }
                    show($('row-conference'));
                }
                if (!data.when && !data.recurrence && !data.location && !data.conference) {
                    hide($('meta'));
                }

                if (data.description) {
                    setText($('desc-title'), t('description'));
                    setText($('desc'), data.description);
                    show($('section-desc'));
                }

                setText($('people-title'), t('attendees'));
                renderPeople();

                setText($('label-accepted'), t('yes'));
                setText($('label-tentative'), t('maybe'));
                setText($('label-declined'), t('no'));
                setText($('note-label'), t('note'));
                $('note').placeholder = t('noteHint');
                updateCount();

                var me = data.attendee || {};
                setText($('reply-as'), t('replyAs', me.name ? me.name + ' (' + me.email + ')' : me.email));

                var current = String(data.partstat || '').toLowerCase();
                var known = isPartStat(current);
                setText($('send'), known ? t('update') : t('send'));

                hide($('view-loading'));
                show($('view-event'));

                if (data.description) {
                    var desc = $('desc');
                    if (desc.scrollHeight - desc.clientHeight > 4) {
                        setText($('desc-toggle'), t('showMore'));
                        show($('desc-toggle'));
                    }
                }

                if (kind === 'cancel') {
                    hide($('respond'));
                    return;
                }

                if (isPartStat(preset)) {
                    select(preset);
                } else if (known) {
                    select(current);
                }
            }

            function updateCount() {
                var used = $('note').value.length;
                setText($('note-count'), used ? used + ' / 512' : '');
            }

            function send() {
                if (inFlight || !isPartStat(selected)) return;
                var btn = $('send');
                inFlight = true;
                btn.disabled = true;
                clearAlert();

                post({
                    token: token,
                    partstat: selected,
                    comment: $('note').value.trim()
                }).then(function (resp) {
                    if (resp && resp.type === 'recorded') {
                        data.partstat = resp.partstat || selected;
                        renderRecorded(String(data.partstat).toLowerCase());
                        return;
                    }
                    inFlight = false;
                    btn.disabled = false;
                    showAlert((resp && resp.message) || t('error'));
                }).catch(function () {
                    inFlight = false;
                    btn.disabled = false;
                    showAlert(t('error'));
                });
            }

            function loadCustomLogo(domain) {
                var target = apiUrl.replace(/\/api\/calendar\/rsvp$/, '') + '/logo';
                if (domain) target += '?domain=' + encodeURIComponent(domain);
                loadLogo($('logo-wrap'), target, 'omit');
            }

            function findOrganizer(resp) {
                var list = (resp && resp.attendees) || [];
                for (var i = 0; i < list.length; i++) {
                    if (list[i].isOrganizer) return list[i];
                }
                return null;
            }

            function organizerDomain(resp) {
                var organizer = findOrganizer(resp);
                var email = organizer && organizer.email;
                var at = email ? String(email).lastIndexOf('@') : -1;
                return at !== -1 ? String(email).slice(at + 1).toLowerCase() : '';
            }

            $('choices').addEventListener('click', function (ev) {
                var btn = ev.target.closest ? ev.target.closest('.choice') : null;
                if (btn) select(btn.getAttribute('data-value'));
            });
            $('choices').addEventListener('keydown', function (ev) {
                var step = ev.key === 'ArrowRight' || ev.key === 'ArrowDown' ? 1
                    : ev.key === 'ArrowLeft' || ev.key === 'ArrowUp' ? -1 : 0;
                if (!step) return;
                ev.preventDefault();
                var at = PARTSTATS.indexOf(selected);
                var next = PARTSTATS[(at + step + PARTSTATS.length) % PARTSTATS.length];
                select(next);
                var node = $('choices').querySelector('.choice[data-value="' + next + '"]');
                if (node) node.focus();
            });
            $('send').addEventListener('click', send);
            $('note').addEventListener('input', updateCount);
            $('desc-toggle').addEventListener('click', function () {
                var clamped = $('desc').classList.toggle('clamped');
                setText($('desc-toggle'), clamped ? t('showMore') : t('showLess'));
                $('desc-toggle').setAttribute('aria-expanded', clamped ? 'false' : 'true');
            });
            $('people-toggle').addEventListener('click', function () {
                peopleExpanded = !peopleExpanded;
                $('people-toggle').setAttribute('aria-expanded', peopleExpanded ? 'true' : 'false');
                renderPeople();
            });
            $('change').addEventListener('click', function () {
                inFlight = false;
                hide($('recorded'));
                show($('respond'));
                $('send').disabled = !selected;
                setText($('send'), t('update'));
            });

            if (!token) { loadCustomLogo(''); fail(null, FALLBACK.invalidLink); return; }

            post({ token: token }).then(function (resp) {
                loadCustomLogo(organizerDomain(resp));
                applyDirection(resp);
                if (resp && resp.labels) labels = resp.labels;
                if (!resp || resp.type !== 'invitation') {
                    fail(resp && resp.title, resp && resp.message);
                    return;
                }
                data = resp;
                renderEvent();
            }).catch(function () {
                loadCustomLogo('');
                fail();
            });
    }

    document.addEventListener('DOMContentLoaded', function () {
        var button = $('theme-toggle');
        if (button) {
            labelToggle(button);
            button.addEventListener('click', function () {
                setTheme(currentTheme() === 'dark' ? 'light' : 'dark');
                labelToggle(button);
            });
            if (media && media.addEventListener) {
                media.addEventListener('change', function () { labelToggle(button); });
            }
        }
        var page = document.body.getAttribute('data-page');
        if (page === 'login') loginPage();
        else if (page === 'rsvp') rsvpPage();
    });
})();
