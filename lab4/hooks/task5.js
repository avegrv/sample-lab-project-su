Java.perform(function() {
	console.log("[Lab4] script is running");

	var nativeHook = Java.use("com.su.lab4.fragments.NativeHookFragment");
	nativeHook.checkPassword.overload("java.lang.String").implementation = function(str) {
		return true;
	}
	console.log("[Lab4] task5 is solved");
})