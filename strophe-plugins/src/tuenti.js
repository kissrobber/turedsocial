/*
    @author: Ruben J Garcia <rubenjgarciab@gmail.com>
    @version: 1.0
    
    This program is distributed under the terms of the MIT license.
    Please see the LICENSE file for details.

    Copyright 2006-2008, OGG, LLC
*/

/**
 *  Handler for initial connection request with Tuenti.
 *
 *  This handler is used to process the initial connection request
 *  response from the BOSH server. It is used to set up authentication
 *  handlers and start the authentication process.
 *
 *  SASL authentication will be attempted if available, otherwise
 *  the code will fall back to legacy authentication.
 *
 *  @param (Strophe.Request) req - The current request.
 */
Strophe.Connection.prototype._connect_tuenti = function (req) {
    Strophe.info("_connect_tuenti was called");

    this.connected = true;
    var bodyWrap = req.getResponse();
    if (!bodyWrap) { return; }

    this.xmlInput(bodyWrap);
    this.rawInput(Strophe.serialize(bodyWrap));

    var typ = bodyWrap.getAttribute("type");
    var cond, conflict;
    if (typ !== null && typ == "terminate") {
        // an error occurred
        cond = bodyWrap.getAttribute("condition");
        conflict = bodyWrap.getElementsByTagName("conflict");
        if (cond !== null) {
            if (cond == "remote-stream-error" && conflict.length > 0) {
                cond = "conflict";
            }
            this._changeConnectStatus(Strophe.Status.CONNFAIL, cond);
        } else {
            this._changeConnectStatus(Strophe.Status.CONNFAIL, "unknown");
        }
        return;
    }

    // check to make sure we don't overwrite these if _connect_cb is
    // called multiple times in the case of missing stream:features
    if (!this.sid) {
        this.sid = bodyWrap.getAttribute("sid");
    }
    if (!this.stream_id) {
        this.stream_id = bodyWrap.getAttribute("authid");
    }
    var wind = bodyWrap.getAttribute('requests');
    if (wind) { this.window = wind; }
    var hold = bodyWrap.getAttribute('hold');
    if (hold) { this.hold = hold; }
    var wait = bodyWrap.getAttribute('wait');
    if (wait) { this.wait = wait; }
    

    var do_sasl_plain = false;

    var mechanisms = bodyWrap.getElementsByTagName("mechanism");
    var i, mech, auth_str, hashed_auth_str;
    if (mechanisms.length > 0) {
        for (i = 0; i < mechanisms.length; i++) {
            mech = Strophe.getText(mechanisms[i]);
            if (mech == 'PLAIN') {
                do_sasl_plain = true;
                break;
            }
        }
    } else {
        // we didn't get stream:features yet, so we need wait for it
        // by sending a blank poll request
        var body = this._buildBody();
        this._requests.push(
            new Strophe.Request(body.tree(),
                                this._onRequestStateChange.bind(this)
                                  .prependArg(this._connect_cb.bind(this)),
                                body.tree().getAttribute("rid")));
        this._throttledRequestHandler();
        return;
    }
    
    if (!do_sasl_plain)	{
    	return;
    }
    
    // Build the plain auth string (barejid null
    // username null password) and base 64 encoded.
    auth_str = this.jid;
    auth_str = auth_str + "\u0000";
    auth_str = auth_str + this.userId;
    auth_str = auth_str + "\u0000";
    auth_str = auth_str + this.sessionId;

    this._changeConnectStatus(Strophe.Status.AUTHENTICATING, null);
    this._sasl_success_handler = this._addSysHandler(
        this._sasl_success_cb.bind(this), null,
        "success", null, null);
    this._sasl_failure_handler = this._addSysHandler(
        this._sasl_failure_cb.bind(this), null,
        "failure", null, null);

    hashed_auth_str = Base64.encode(auth_str);
    this.send($build("auth", {
        xmlns: Strophe.NS.SASL,
        mechanism: "PLAIN"
    }).t(hashed_auth_str).tree());
};

/**
 *  Starts the connection process with Tuenti XMPP Chat Server.
 *
 *  As the connection process proceeds, the user supplied callback will
 *  be triggered multiple times with status updates.  The callback
 *  should take two arguments - the status code and the error condition.
 *
 *  The status code will be one of the values in the Strophe.Status
 *  constants.  The error condition will be one of the conditions
 *  defined in RFC 3920 or the condition 'strophe-parsererror'.
 *
 *  Please see XEP 124 for a more detailed explanation of the optional
 *  parameters below.
 *
 *  @param (String) jid - The user's JID. It must be tuentid@xmppX.tuenti.com,
 *  	where tuentid is the number id of the tuenti profile and xmppX is the 
 *  	server of the user's chat
 *  @param (String) userId - The user's tuenti Id
 *  @param (String) sessionId - The actual tuenti session Id
 *  @param (Function) callback The connect callback function.
 *  @param (Integer) wait - The optional HTTPBIND wait value.  This is the
 *      time the server will wait before returning an empty result for
 *      a request.  The default setting of 60 seconds is recommended.
 *      Other settings will require tweaks to the Strophe.TIMEOUT value.
 *  @param (Integer) hold - The optional HTTPBIND hold value.  This is the
 *      number of connections the server will hold at one time.  This
 *      should almost always be set to 1 (the default).
 */
Strophe.Connection.prototype.tuentiConnect = function (jid, userId, sessionId, callback, wait, hold){
    this.jid = jid;
    this.userId = userId;
    this.sessionId = sessionId;
    this.connect_callback = callback;
    this.disconnecting = false;
    this.connected = false;
    this.authenticated = false;
    this.errors = 0;

    this.wait = wait || this.wait;
    this.hold = hold || this.hold;

    // parse jid for domain and resource
    this.domain = Strophe.getDomainFromJid(this.jid);

    // build the body tag
    var body = this._buildBody().attrs({
        to: this.domain,
        "xml:lang": "en",
        wait: this.wait,
        hold: this.hold,
        content: "text/xml; charset=utf-8",
        ver: "1.6",
        "xmpp:version": "1.0",
        "xmlns:xmpp": Strophe.NS.BOSH
    });

    this._changeConnectStatus(Strophe.Status.CONNECTING, null);

    this._requests.push(
        new Strophe.Request(body.tree(),
                            this._onRequestStateChange.bind(this)
                                .prependArg(this._connect_tuenti.bind(this)),
                            body.tree().getAttribute("rid")));
    this._throttledRequestHandler();
};