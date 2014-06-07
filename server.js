
const ASSERT = require("assert");
const PASSPORT = require("passport");
const PASSPORT_GITHUB = require("passport-github");


var passport = null;

require("io.pinf.server.www").for(module, __dirname, function(app, config, HELPERS) {

	config = config.config;

    ASSERT.equal(typeof config.passport.github.clientID, "string");
    ASSERT.equal(typeof config.passport.github.clientID, "string");
    ASSERT.equal(typeof config.passport.github.clientSecret, "string");
    ASSERT.equal(typeof config.passport.github.callbackURL, "string");
    ASSERT.equal(typeof config.passport.github.scope, "string");

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

    app.get(/^\/login\/github$/, passport.authenticate("github", {
        failureRedirect: "/login/fail"
    }), function(req, res) {
        if (!req.session.passport.user || !req.session.passport.user.id) {
            res.writeHead(302, {
                "Location": "/login/fail"
            });
            return res.end();
        }
        if (!req.session.authorized) {
            req.session.authorized = {};
        }
        req.session.authorized.github = req.session.passport.user;
        delete req.session.passport;
        res.writeHead(302, {
            "Location": "/"
        });
        return res.end();
    });

    app.get(/^\/logout\/github$/, function(req, res) {
        if (req.session.authorized && req.session.authorized.github) {
            delete req.session.authorized.github;
        }
        res.writeHead(302, {
            "Location": "/"
        });
        return res.end();
    });

});
