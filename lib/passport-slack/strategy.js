/**
 * Module dependencies.
 */
var util = require('util')
    , OAuth2Strategy = require('passport-oauth').OAuth2Strategy;


/**
 * `Strategy` constructor.
 *
 * The Slack authentication strategy authenticates requests by delegating
 * to Slack using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Slack application's client id
 *   - `clientSecret`  your Slack application's client secret
 *   - `callbackURL`   URL to which Slack will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new SlackStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/slack/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || 'https://slack.com/oauth/authorize';
    options.tokenURL = options.tokenURL || 'https://slack.com/api/oauth.access';
    this.testUrl = options.testUrl || "https://slack.com/api/auth.test?token=";
    this.profileUrl = options.profileUrl || "https://slack.com/api/users.info";

    OAuth2Strategy.call(this, options, verify);
    this.name = 'slack';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Slack.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `slack`
 *   - `id`               the user's ID
 *   - `displayName`      the user's username
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
    //this._oauth2.useAuthorizationHeaderforGET(true);
    var self = this;
    this.get(this.testUrl, accessToken, function (err, body, res) {
        if (err) {
            return done(err);
        } else {
            try {
                var json = JSON.parse(body);
                self.get(self.profileUrl+"?user="+json.user_id + "&token=", accessToken, function (err, body, res) {
                        if (err) {
                            return done(err);
                        } else {
                            try {
                                var json = JSON.parse(body);

                                if (!json.ok) {
                                    done(json.error ? json.error : body);
                                } else {
                                    var profile = {
                                        provider: 'Slack'
                                    };
                                    profile.id = json.user.id;
                                    profile.displayName = json.user && json.user.profile && ( json.user.profile.real_name || json.user.profile.email ) ;
                                    profile.emails  = [{"type":"primary", value: json.user && json.user.profile && json.user.profile.email }]

                                    profile.name = { givenName: json.user.profile.first_name, familyName: json.user.profile.last_name };
                                    profile.title = json.user.profile.title;
                                    profile.phone = json.user.profile.phone;
                                    profile.skype = json.user.profile.skype;

                                    profile.photos   = [];
                                    if ( json.user && json.user.profile && json.user.profile.image_24 )
                                        profile.photos.push({value: json.user.profile.image_24, size: 24 });
                                    if ( json.user && json.user.profile && json.user.profile.image_32 )
                                        profile.photos.push({value: json.user.profile.image_32, size: 32 });
                                    if ( json.user && json.user.profile && json.user.profile.image_48 )
                                        profile.photos.push({value: json.user.profile.image_48, size: 48 });
                                    if ( json.user && json.user.profile && json.user.profile.image_72 )
                                        profile.photos.push({value: json.user.profile.image_72, size: 72 });
                                    if ( json.user && json.user.profile && json.user.profile.image_192 )
                                        profile.photos.push({value: json.user.profile.image_192, size: 192 });


                                    profile._raw = body;
                                    profile._json = json;

                                    done(null, profile);
                                }
                            } catch (e) {
                                done(e);
                            }


                        }
                    });
                }
            catch
                (e)
                {
                    done(e);
                }
            }
        }
        )
        ;
    }

    /** The default oauth2 strategy puts the access_token into Authorization: header AND query string
     * which is a violation of the RFC so lets override and not add the header and supply only the token for qs.
     */
    Strategy.prototype.get = function (url, access_token, callback) {
        this._oauth2._request("GET", url + access_token,  {}, "", "", callback);
    };

    Strategy.prototype.authorizationParams = function(options) {
      var params = {};
      if (options.team){
        params['team'] = options.team;
      } 
      return params;
    };

    /**
     * Expose `Strategy`.
     */
    module.exports = Strategy;