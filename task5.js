Java.perform(function () {
    var pass = Java.use("com.su.lab4.fragments.NativeHookFragment");
    pass.checkPassword.implementation = function(str) {
	return true
    };
});