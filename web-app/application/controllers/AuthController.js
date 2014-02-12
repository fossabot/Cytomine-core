var AuthController = Backbone.Router.extend({
    loginDialog : null,
    logoutDialog : null,

    routes: {
        "forgotPassword" : "forgotPassword",
        "forgotUsername" : "forgotUsername",
        "restoreLogin" : "restoreLogin"
    },
    restoreLogin : function() {
        this.loginDialog.restoreLogin();
        window.app.navigate("#", false);
    },
    forgotUsername : function() {
        this.loginDialog.forgotUsername();
    },
    forgotPassword : function() {
        this.loginDialog.forgotPassword();
    },

    login: function () {
        this.loginDialog = new LoginDialogView({});
        this.loginDialog.render();
    },
    logout: function () {
        this.logoutDialog = new LogoutDialogView({});
        this.logoutDialog.render();
    },
    doForgotUsername : function () {
        var app = new ApplicationView(); //in order to use message function
        var data = $("#login-form").serialize(); //should be in LoginDIalogView
        var self = this;
        $.ajax({
            url: 'login/forgotUsername',
            type: 'post',
            dataType: 'json',
            data: data,
            success: function (data) {
                app.message("Success", "Check your inbox", "success");
                window.app.navigate("#restoreLogin", true);
            },
            error: function (data) {
                var resp = $.parseJSON(data.responseText);
                app.message("Error", resp.message, "error");
            }
        });
        return false;
    },
    doForgotPassword : function () {
        var app = new ApplicationView(); //in order to use message function
        var data = $("#login-form").serialize(); //should be in LoginDIalogView
        var self = this;
        $.ajax({
            url: 'login/forgotPassword',
            type: 'post',
            dataType: 'json',
            data: data,
            success: function (data) {
                app.message("Success", "Check your inbox", "success");
                window.app.navigate("#restoreLogin", true);
            },
            error: function (data) {
                var resp = $.parseJSON(data.responseText);
                app.message("Error", resp.message, "error");
            }
        });
        return false;
    },
    doLogin: function () {
        var app = new ApplicationView(); //in order to use message function
        var data = $("#login-form").serialize(); //should be in LoginDIalogView
        var self = this;
        $.ajax({
            url: 'j_spring_security_check',
            type: 'post',
            dataType: 'json',
            data: data,
            success: function (data) {
                app.message("Welcome", "You are logged as " + data.fullname, "", "success");
                new UserModel({id: data.id}).fetch({
                    success: function (model, response) {
                        window.app.status.user = {
                            authenticated: true,
                            id: data.id,
                            model: model,
                            filenameVisible : true
                        }
                        self.loginDialog.close();
                        window.app.startup();
                    }
                });

            },
            error: function (data) {
                var resp = $.parseJSON(data.responseText);
                $('#submit-login').attr('disabled', 'disabled');
                $('#login-confirm').effect("shake", { times: 2 }, 100);
                setTimeout(function () {
                    $('#submit-login').removeAttr('disabled');
                }, 400);
                app.message("Error", resp.message, "error");
            }
        });
        return false;
    }
});