Java.perform(function() {
	console.log("[Lab4] script is running");
		
	var encryptionUtils = Java.use("com.su.lab4.utils.EncryptionUtil");
	encryptionUtils.encrypt.overload("java.lang.String", "java.lang.String").implementation = function(key, str) {
		return key;
	}
	console.log("[Lab4] task3 is solved");
})