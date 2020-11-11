Java.perform(function() {
	console.log("[*] Run hook.js");

	// 2
	var rootUtil = Java.use("com.su.lab4.utils.RootUtil");
	rootUtil.isRootAvailable.implementation = function() {
		return false;
	}
	
	// 3
	var encUtils = Java.use("com.su.lab4.utils.EncryptionUtil");
	encUtils.encrypt.overload("java.lang.String", "java.lang.String").implementation = function(key, str) {
		return key;
	}
	
	//4
	var pinner = Java.use("okhttp3.CertificatePinner");
	pinner.check.overload("java.lang.String", "java.util.List").implementation = function(str1, str2) {
                return;
        }
	pinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function(str1, str2) {
		return;
	}

	//5
	var nativeHook = Java.use("com.su.lab4.fragments.NativeHookFragment");
	nativeHook.checkPassword.overload("java.lang.String").implementation = function(str) {
		return true;
	}
	
	//1
	var pinFragment = Java.use("com.su.lab4.fragments.PinBypassFragment");
        for (var i = 0; i < 1000000; i++) {
                var pin = i.toString()//.padStart(4, "0");
                //console.log(pin);
                if(pinFragment.checkPin(pin)) {
                        console.log(pin);
			break;
                }
        }
        console.log("BruteForce finished");
})
