Java.perform(function() {
	console.log("[Lab4] script is running");
	
	var rootUtil = Java.use("com.su.lab4.utils.RootUtil");
	rootUtil.isRootAvailable.implementation = function() {
		return false;
	}
	console.log("[Lab4] task2 is solved");
})