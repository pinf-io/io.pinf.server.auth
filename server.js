
const ASSERT = require("assert");
const PATH = require("path");
const FS = require("fs");
const PASSPORT = require("passport");
const PASSPORT_GITHUB = require("passport-github");
const REQUEST = require("request");
const WAITFOR = require("waitfor");
const DEEPCOPY = require("deepcopy");


var passport = null;

var pioConfig = JSON.parse(FS.readFileSync(PATH.join(__dirname, "../.pio.json")));

require("io.pinf.server.www").for(module, __dirname, function(app, config, HELPERS) {

	config = config.config;

    ASSERT.equal(typeof config.passport.github.clientID, "string");
    ASSERT.equal(typeof config.passport.github.clientID, "string");
    ASSERT.equal(typeof config.passport.github.clientSecret, "string");
    ASSERT.equal(typeof config.passport.github.callbackURL, "string");
    ASSERT.equal(typeof config.passport.github.scope, "string");

    if (!config.passport.github.clientID) {
        app.use(function (req, res, next) {
            res.writeHead(500);
            return res.end("Authentication service is not configured!");
        });
        return;
    }

	passport = new PASSPORT.Passport();
	passport.serializeUser(function(user, done) {
	    done(null, user);
	});
	passport.deserializeUser(function(obj, done) {
	    done(null, obj);
	});
    passport.use(new PASSPORT_GITHUB.Strategy(config.passport.github, function(accessToken, refreshToken, profile, done) {
        return done(null, {                    
            "id": profile.id,
            "email": profile.emails[0].value,
            "username": profile.username,
            "accessToken": accessToken
        });
    }));

    app.use(passport.initialize());
    app.use(passport.session());

    app.use(function (req, res, next) {
        res.view = {
            authorized: (req.session && req.session.authorized) || false
        };
        return next();
    });

}, function(app, config) {

    config = config.config;

    if (!passport) return;

    var configuredScopes = config.passport.github.scope.replace(/\s/g, "").split(",");

    function logoutGithub(req) {
        if (req.session.authorized && req.session.authorized.github) {
            delete req.session.authorized.github;
        }
        // If only groups and roles present.
        if (req.session.authorized && typeof req.session.authorized === "object" && Object.keys(req.session.authorized).length === 2) {
            req.session.authorized = null;
        }
    }

    var temporaryAuthCodes = {};
    app.get(/^\/authorize\/github$/, function(req, res, next) {
        if (!req.query.callback) {
            return next(new Error("'callback' query parameter must be set for url: " + req.url));
        }
        if (req.query["session-auth-code"]) {
            req.session.sessionAuthCodeAfterLogin = req.query["session-auth-code"];
        }
        req.session.redirectAfterLogin = req.query.callback;
        res.writeHead(302, {
            "Location": "/login/github"
        });
        return res.end();
    });

    app.get(/^\/login\/fail$/, function(req, res, next) {
        console.log("SESSION ON FAIL", req.session);
        return next();
    });

    app.get(/^\/login\/github$/, function(req, res, next) {
        if (req.query) {
            if (req.query.returnTo) {
                req.session.redirectAfterLogin = req.query.returnTo;
            }
            if (typeof req.query.requestScope !== "undefined") {
                if (!req.session.requested) {
                    req.session.requested = {};
                }
                if (!req.session.requested.github) {
                    req.session.requested.github = {};
                }
                if (!req.session.requested.github.scope) {
                    req.session.requested.github.scope = [];
                }
                req.session.requested.github.scope = req.session.requested.github.scope.concat(req.query.requestScope.split(","));
            }
        }
        function unique(_scopes) {
            var scopes = {};
            _scopes.forEach(function(scope) {
                scopes[scope] = true;
            });
            return Object.keys(scopes);
        }
        if (
            req.session.requested &&
            req.session.requested.github &&
            req.session.requested.github.scope
        ) {
            req.session.passport = {};
            logoutGithub(req);
            passport._strategies.github._scope = unique(configuredScopes.concat(req.session.requested.github.scope).concat((req.session.keep && req.session.keep.github && req.session.keep.github.scope) || [])).join(",");
            delete req.session.requested.github.scope;
        } else {
            passport._strategies.github._scope = unique(configuredScopes.concat((req.session.keep && req.session.keep.github && req.session.keep.github.scope) || [])).join(",");
        }
        if (!req.session.keep) {
            req.session.keep = {};
        }
        if (!req.session.keep.github) {
            req.session.keep.github = {};
        }
        req.session.keep.github.scope = passport._strategies.github._scope.split(",");
//console.log("before login", JSON.stringify(req.session, null, 4));
        return next();
    }, passport.authenticate("github", {
        failureRedirect: "/login/fail?reason=NO_PASSPORT_USER"
    }), function(req, res, next) {
        if (!req.session.passport || !req.session.passport.user || !req.session.passport.user.id) {
            console.log("Redirect to fail.", "req.session", req.session);
            res.writeHead(302, {
                "Location": "/login/fail?reason=NO_SESSION"
            });
            return res.end();
        }
        return resolveGroups(res.r, config, req.session.passport.user, function(err, groups, roles) {
            if (err) {
                if (err.code === 403 && typeof err.requestScope !== "undefined") {
                    if (!req.session.requested) {
                        req.session.requested = {};
                    }
                    if (!req.session.requested.github) {
                        req.session.requested.github = {};
                    }
                    if (!req.session.requested.github.scope) {
                        req.session.requested.github.scope = [];
                    }
                    if (req.session.requested.github.scope.indexOf(err.requestScope) === -1) {
                        req.session.requested.github.scope.push(err.requestScope);
                    }
                    if (
                        req.session.authorized &&
                        req.session.authorized.github
                    ) {
                        delete req.session.authorized.github;
                    }
                    res.writeHead(302, {
                        "Location": "/login/github?why=elevated-oauth-scope"
                    });
                    return res.end();
                }
                return next(err);
            }

            if (!req.session.authorized) {
                req.session.authorized = {};
            }
            req.session.authorized.links = {
                "fetch": "http://" + req.headers.host + "/user/session/authorized?session-auth-code={{session-auth-code}}"
            };
            req.session.authorized.github = JSON.parse(JSON.stringify(req.session.passport.user));
            req.session.authorized.github.links = {
                // TODO: Subdomain and port as well as host should come from config.
                // TODO: Make session id hostname agnostic if using equivalent hostnames.
                //"requestScope": "http://io-pinf-server-auth." + req.headers.host + ":8013/login/github?requestScope={{scope}}&returnTo={{callback}}"
                "requestScope": "http://" + req.headers.host + "/login/github?requestScope={{scope}}&returnTo={{callback}}"
            };
            req.session.authorized.github.scope = req.session.keep.github.scope;
            req.session.passport = {};

            req.session.authorized.groups = groups;
            req.session.authorized.roles = roles;
console.log("after login", JSON.stringify(req.session, null, 4));

            if (req.session.redirectAfterLogin && req.session.redirectAfterLogin.indexOf(pioConfig.config.pio.hostname) === -1) {
                return next(new Error("'req.session.redirectAfterLogin' does not point to hostname '" + pioConfig.config.pio.hostname + "'!"));
            }

            if (req.session.sessionAuthCodeAfterLogin) {
                req.session.keep.temporaryAuthCode = req.session.sessionAuthCodeAfterLogin;
                temporaryAuthCodes[req.session.sessionAuthCodeAfterLogin] = DEEPCOPY(req.session.authorized);
                delete req.session.sessionAuthCodeAfterLogin;
            } else
            if (req.session.keep && req.session.keep.temporaryAuthCode) {
                temporaryAuthCodes[req.session.keep.temporaryAuthCode] = DEEPCOPY(req.session.authorized);
            }

            var redirectTo = req.session.redirectAfterLogin || config.loggedInRedirect || "/";
            console.log("Redirecting to:", redirectTo);
            res.writeHead(302, {
                "Location": redirectTo
            });
            delete req.session.redirectAfterLogin;
            return res.end();
        });
    });

    function ensureAuthenticated(req, res, next) {
        if (res.view.authorized) {
            return next();
        }
        function triggerDefaultLogin(err) {
            if (err) return next(err);
            res.writeHead(302, {
                "Location": "/"
            });
            return res.end();
        }
        if (res.triggerLogin) {
            return res.triggerLogin(req, res, function(err) {
                return triggerDefaultLogin(err);
            });
        }
        return triggerDefaultLogin();
    }

    app.get(/^\/user\/session\/authorized$/, function(req, res, next) {
        if (
            req.query["session-auth-code"] &&
            req.query["session-auth-code"] !== "sidcookie" &&
            temporaryAuthCodes[req.query["session-auth-code"]]
        ) {
            var payload = temporaryAuthCodes[req.query["session-auth-code"]];
// NOTE: We don't delete this code any more as we treat it as a token.
// TODO: Use a proper token exchange lib.
//            delete temporaryAuthCodes[req.query["session-auth-code"]];
            payload.$status = 200;
            payload = JSON.stringify(payload, null, 4);
            payload = payload.replace(/\{\{session-auth-code\}\}/g, req.query["session-auth-code"]);
            res.writeHead(200, {
                "Content-Type": "application/json",
                "Content-Length": payload.length
            });
            return res.end(payload);
        }
        res.triggerLogin = function(req, res, next) {
            if (req.headers["accept"] === "application/json") {
                if (!req.query["session-auth-code"]) {
                    return next(new Error("'session-auth-code' parameter must be set for url '" + req.url + "'!"));
                }
                var payload = JSON.stringify({
                    "$status": 403,
                    "$location": "/authorize/github?session-auth-code=" + req.query["session-auth-code"]
                }, null, 4);
                res.writeHead(200, {
                    "Content-Type": "application/json",
                    "Content-Length": payload.length
                });
                return res.end(payload);
            }
            return next();
        }
        return next();
    }, ensureAuthenticated, function(req, res, next) {
        var payload = DEEPCOPY(req.session.authorized);
        payload.$status = 200;
        payload = JSON.stringify(payload, null, 4);
        payload = payload.replace(/\{\{session-auth-code\}\}/g, "sidcookie");
        res.writeHead(200, {
            "Content-Type": "application/json",
            "Content-Length": payload.length
        });
        return res.end(payload);
    });

    app.get(/^\/logout\/github$/, function(req, res) {
        logoutGithub(req);
        res.writeHead(302, {
            "Location": "/"
        });
        return res.end();
    });

    app.get(/^\/$/, function(req, res, next) {
        if (res.view.authorized && config.loggedInRedirect) {
            console.log("Redirecting to '" + config.loggedInRedirect + "' due to 'loggedInRedirect' config.");
            return res.redirect(config.loggedInRedirect);
        }
        return next();
    });

});

function resolveGroups(r, config, userInfo, callback) {

    const DB_NAME = "devcomp";
    const TABLE_NAME = "io.pinf.server.auth".replace(/\./g, "_");

    var authorizedGroups = [];
    var authorizedRoles = [];
    var waitfor = WAITFOR.serial(function(err) {
        if (err) return callback(err);
        return callback(null, authorizedGroups, authorizedRoles);
    });
    function callGithub(path, callback) {
        var url = "https://api.github.com" + path;
        return REQUEST({
            url: url,
            headers: {
                "User-Agent": "nodejs/request",
                "Authorization": "token " + userInfo.accessToken
            },
            json: true
        }, function (err, res, body) {
            if (err) return callback(err);
            if (res.statusCode === 403 || res.statusCode === 404) {
                console.error("Got status '" + res.statusCode + "' for url '" + url + "'! This is likely due to NOT HAVING ACCESS to this API call because your OAUTH SCOPE is too narrow! See: https://developer.github.com/v3/oauth/#scopes", res.headers);
                var scope = null;
                if (/^\/orgs\/([^\/]+)\/teams$/.test(path)) {
                    scope = "read:org";
                } else
                if (/^\/teams\/([^\/]+)\/members\/([^\/]+)$/.test(path)) {
                    scope = "read:org";
                }
                if (scope) {
                    console.log("We are going to start a new oauth session with the new require scope added ...");
                    var err = new Error("Insufficient privileges. Should start new session with added scope: " + scope);
                    err.code = 403;
                    err.requestScope = scope;
                    return callback(err);
                }
                return callback(new Error("Insufficient privileges. There should be a scope upgrade handler implemented for url '" + url + "'!"));
            }
            return callback(null, res, body);
        });
    }
    function getTeamInfo(orgName, teamName, callback) {
        console.log("getTeamInfo", orgName, teamName);
        return r.getCached(DB_NAME, TABLE_NAME, "cache", "github.org['" + orgName + "'].team['" + teamName + "']", function(err, cached, teamCache) {
            if (err) return callback(err);
            // TODO: Force cache refresh if requested!
            if (cached) return callback(null, cached);
            return callGithub("/orgs/" + orgName + "/teams", function(err, res, teams) {
                if (err) return callback(err);
                if (!teams) {
                    return callback(null, null);
                }
                for (var i = teams.length ; i>0 ; i--) {
                    if (teams[i-1].slug === teamName) {
                        return r.getCached(DB_NAME, TABLE_NAME, "cache", "github.org['" + orgName + "'].team['" + teamName + "'].members", function(err, cached, membersCache) {
                            if (err) return callback(err);

                            return callGithub("/teams/" + teams[i-1].id + "/members", function(err, res, members) {
                                if (err) return callback(err);
                                if (!members) {
                                    return callback(null, null);
                                }
                                return membersCache(members, function(err) {
                                    if (err) return callback(err);

                                    return teamCache({
                                        id: teams[i-1].id,
                                        permission: teams[i-1].permission
                                    }, callback);
                                });
                            });
                        });
                    }
                }
                return callback(null, null);
            });
        });
    }
    function isMemberOfTeam(orgName, teamName, callback) {
        console.log("isMemberOfTeam", orgName, teamName);
        return r.getCached(DB_NAME, TABLE_NAME, "cache", "github.org['" + orgName + "'].team['" + teamName + "'].members", function(err, members) {
            if (err) return callback(err);
            if (!members) {
                return callback(new Error("An OWNER must login before any other user to populate admin members!"));
            }
            for (var i = members.length ; i>0 ; i--) {
                if (members[i-1].id === userInfo.id) {
                    return callback(null, true);
                }
            }
            return callback(null, false);
        });
    }
    if (config && config.groups) {
        for (var name in config.groups) {
            waitfor(name, function (name, callback) {
                console.log("Resolve group '" + name + "' for user '" + userInfo.username + "'");
                if (/^https?:\/\/github\.com\/\*$/.test(config.groups[name].inherits)) {                    
                    authorizedGroups.push(name);
                    authorizedRoles.push(config.groups[name].role);                    
                } else {
                    var m = config.groups[name].inherits.match(/^https?:\/\/github\.com\/orgs\/([^\/]+)\/teams\/([^\/]+)$/);
                    if (!m) {
                        return callback(new Error("Inherits URI '" + config.groups[name].inherits + "' not supported! This is a config issue."));
                    }
                    return getTeamInfo(m[1], m[2], function(err, teamInfo) {
                        if (err) return callback(err);
                        return isMemberOfTeam(m[1], m[2], function(err, isMember) {
                            if (err) return callback(err);
                            if (isMember) {
                                authorizedGroups.push(name);
                                authorizedRoles.push(config.groups[name].role);                    
                            }
                            return callback(null);
                        });
                    });
                }
                return callback(null);
            });
        }
    }
    return waitfor();
}
