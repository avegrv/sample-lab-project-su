Java.perform(function () {
    var key = Java.use("com.su.lab4.utils.EncryptionUtil");
    key.encrypt.implementation = function(str1, str2) {
	send(str1)
	return str1
    };
});