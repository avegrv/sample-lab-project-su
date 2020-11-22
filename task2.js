Java.perform(function () {
    var root_check = Java.use("com.su.lab4.utils.RootUtil");
    root_check.isRootAvailable.implementation = function(var_0) {
        return false
    };
});