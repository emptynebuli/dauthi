// thanks: https://awakened1712.github.io/hacking/hacking-frida/
function bytes2hex(array) {
    var result = '';
    for (var i = 0; i < array.length; ++i)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    return result;
};

function edianPTR(array) {
    var result = '';
    for (var i = 4; i >= 0; i--)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    console.log('[*] PTR: 0x'+result)
    return ptr('0x'+result)
}

// setTimeout is used to defines the timeout counter before the Java.perform function is call
setTimeout(function(){
    if (Java.available) {
    // Java.perform is the Frida function call to start injection
        Java.perform(function (){
            var SplashScreenViewModel = Java.use("com.blackberry.ema.ui.SplashScreenViewModel");
            let UtilT = Java.use("com.blackberry.emalib.util.t");
            let LoggingLog = Java.use("com.good.gd.apache.commons.logging.Log");
            var UtilE = Java.use("com.blackberry.emalib.util.e");
            var h0dooor = Java.use('com.blackberry.ema.service.h0Dooor.hooodor.h0dooor');
            var EnrollInterface = Java.use("com.blackberry.enrollment.EnrollInterface");
            var EnrollInterface = Java.use("com.blackberry.enrollment.EnrollInterface");

            // Bypass Frida detection
            SplashScreenViewModel["hooDoR"].implementation = function () {
                console.log('[*] Caught SplashScreenViewModel');
                console.log('[+] Bypass Hooking Detection');
                this._Hod0R.value = false
                this.Hod0r.value = false
                return false
            };

            // Change App setting for Debug Logging
            UtilT["hodor"].implementation = function () {
                console.log('[*] Caught emalib.util.t')
                console.log('[*] Currenlty Log Level: '+this.hodor())
                let contextImpl = Java.cast(this._hodoR.value, Java.use("android.app.ContextImpl"))
                let SharedPreferencesImpl = Java.cast(contextImpl.getSharedPreferences("com.rim.mobilefusion.client", 0), Java.use("android.app.SharedPreferencesImpl"))
                let SharedPreferencesImpl_edit = Java.cast(SharedPreferencesImpl.edit(), Java.use("android.app.SharedPreferencesImpl$EditorImpl"))
                let putDebug = Java.cast(SharedPreferencesImpl_edit.putBoolean("debugLoggingMode", true), Java.use("android.app.SharedPreferencesImpl$EditorImpl"))
                putDebug.apply()
                console.log('[+] Set Debug Logger')
                return true;
            };

            // Modify debug logger check
            LoggingLog["isDebugEnabled"].implementation = function () {
                console.log('[*] Caught commons.logging.Log');
                console.log('[+] Setting Debug Logging State');
                return true;
            };

            // Get HMAC-SHA512 Buffer Strings
            var hmacBuff = new Array();
            UtilE["hodor"].implementation = function (str) {
                if (str.length < 51) { // DB strings are about 51 characters
                    hmacBuff.push(str)
                }
                return this.hodor(str);
            };

            // Get HmacSHA512 Result Value
            UtilE["hodoR"].implementation = function () {
                // Add static salt
                hmacBuff.push("0x"+bytes2hex(this._hodor.value))
                console.log("[+] HMAC-Buff: "+JSON.stringify(hmacBuff))
                // Pull HMAC Key
                console.log('[+] HMAC Key: '+this.hoDoR.value)

                let ret = this.hodoR();
                console.log('[+] B64 HmacSHA512: ' + ret);
                return ret;
            };

            // Get Discovery POST XML Payload
            h0dooor["hod0R"].implementation = function(str1, str2) {
                console.log("[*] Disco URI: "+str1);
                console.log("[*] Disco XML POST Body: \n"+str2);

                return this.hod0R(str1, str2)
            };

            // Enrollment Cleartext Request
            EnrollInterface["enrollment_create"].implementation = function (str, str2, cArr, str3, str4, str5, str6, str7, str8) {
                console.log('[*] Caught Enrollment')
                console.log('  [+] PIN: '+str)
                console.log('  [+] User: '+str2)
                console.log('  [+] Password Char: '+cArr)
                console.log('  [+] API v: '+str3)
                console.log('  [+] Device: '+str7)
                console.log('  [+] Ciper: '+str8)

                let ret = this.enrollment_create(str, str2, cArr, str3, str4, str5, str6, str7, str8);
                console.log('[+] EnrollmentID: ' + ret);
                return ret;
            };

            // Enrollment Return Data
            EnrollInterface["enrollment_get_request"].implementation = function (j) {
                let ret = this.enrollment_get_request(j);
                console.log('[*] Encrypted Enrollment Data: \n' + ret);
                return ret;
            };            
            var libspekexp_addr = Module.findBaseAddress("libspekexp.so")
            console.log("[+] libspekexp_addr is: "+libspekexp_addr)

            if (libspekexp_addr) {
                // console.log('[*] Libspekexp Exports: ')
                // Process.findModuleByName("libspekexp.so").enumerateExports().forEach(function(exp) {
                //     if (exp.address != null) {
                //         if (exp.name.includes("enrollment")) {
                //             console.log("  [+] Enrollment Interface: "+exp.name)
                //         } else if (exp.name.includes("aes")) {
                //             console.log("  [+] AES Export: "+exp.name)
                //         }
                //     }
                // })

                var enrollment_create = Module.findExportByName("libspekexp.so", "enrollment_create")
                console.log("[+] enrollment_create is: "+enrollment_create)
                var speke_getRandom = Module.findExportByName("libspekexp.so", "speke_getRandom")
                console.log("[+] speke_getRandom is: "+speke_getRandom)
                var speke_negotiator_create = Module.findExportByName("libspekexp.so", "speke_negotiator_create")
                console.log("[+] speke_negotiator_create is: "+speke_negotiator_create)
                var speke_negotiator_get_client_public_key = Module.findExportByName("libspekexp.so", "speke_negotiator_get_client_public_key")
                console.log("[+] speke_negotiator_get_client_public_key is: "+speke_negotiator_get_client_public_key)
                var speke_generateClientKeys = Module.findExportByName("libspekexp.so", "speke_generateClientKeys")
                console.log("[+] speke_generateClientKeys is: "+speke_generateClientKeys)
                var speke_aes_encrypt = Module.findExportByName("libspekexp.so", "speke_aes_encrypt")
                console.log("[+] speke_aes_encrypt is: "+speke_aes_encrypt)

                // Key/IV Recovery
                // speke_aes_encrypt(int param_1,int param_2,long param_3,long param_4,long param_5,void *param_6,long param_7,long param_8,size_t *param_9,void **param_10)
                Interceptor.attach(speke_aes_encrypt, {
                    onEnter: function (args) {
                        console.log("[*] HIT speke_aes_encrypt")
                        var cLength = args[2].toInt32()
                        var ivLength = args[4].toInt32()

                        console.log("[+] aes256-CBC Key: 0x"+bytes2hex(new Uint8Array(args[3].readByteArray(cLength))))
                        console.log("[+] aes256-CBC IV: 0x"+bytes2hex(new Uint8Array(args[5].readByteArray(ivLength))))
                    },
                    onLeave: function () {}
                })

                // enrollment_create(char *ptr_pin,char *ptr_usr,char *ptr_pass,ulong ptr_passLength,char *param_5,char *param_6,void *param_7,ulong param_8,char *param_9,void **param_10,char *param_11,char *cipher)
                Interceptor.attach(enrollment_create, {
                    onEnter: function (args) {
                        console.log("[*] HIT enrollment_create NATIVE")
                        console.log("[+] Encrypted User: "+Memory.readCString(args[0]))
                    },
                    onLeave: function () {}
                })

                // speke_getRandom(size_t param_1,void **param_2)
                var rndLength, getRandom1
                Interceptor.attach(speke_getRandom, {
                    onEnter: function (args) {
                        console.log("[*] HIT speke_getRandom")
                        rndLength = args[0].toInt32()
                        getRandom1 = args[1]
                    },
                    onLeave: function () {
                        var buf1 = getRandom1.readByteArray(5)
                        let p1 = edianPTR(new Uint8Array(buf1))
                        console.log("[+] RAND TransactionID: 0x"+bytes2hex(new Uint8Array(p1.readByteArray(rndLength))))
                    }
                })

                // int speke_negotiator_create(undefined8 passwd,undefined8 passwdLength,char *param_3,void **param_4)
                var negCreate1
                Interceptor.attach(speke_negotiator_create, {
                    onEnter: function (args) {
                        console.log("[*] HIT speke_negotiator_create")
                        negCreate1 = args[3]

                        console.log("[+] SPEKE Cipher: "+Memory.readCString(args[2]))
                    },
                    onLeave: function (retval) {
                        console.log('[**] speke_negotiator_create RET: '+retval)

                        var p1 = edianPTR(new Uint8Array(negCreate1.readByteArray(5)))
                        var p2 = edianPTR(new Uint8Array(p1.readByteArray(5)))
                        console.log('[**] speke_negotiator_create RET ARGS[3]: 0x'+bytes2hex(new Uint8Array(p2.readByteArray(66))))
                    }
                })

                // (0xf0,passwdLength,passwd,(long)__ptr + 8,__ptr,(long)__ptr + 0x18,(long)__ptr + 0x10)
                var clientKey = new Array()
                Interceptor.attach(speke_generateClientKeys, {
                    onEnter: function (args) {
                        console.log("[*] HIT speke_generateClientKeys")
                        for (var i=0; i<8; ++i) {
                            clientKey.push(args[i])
                        }
                    },
                    onLeave: function (retval) {
                        console.log('[**] speke_generateClientKeys RET: '+JSON.stringify(retval))
                        var priLength = clientKey[3].readU32()
                        var pubLength = clientKey[5].readU32()

                        let p1 = edianPTR(new Uint8Array(clientKey[4].readByteArray(5)))
                        console.log("[+] SPEKE(priKey) Length: "+priLength+" Val: 0x"+bytes2hex(new Uint8Array(p1.readByteArray(priLength))))
                        let p2 = edianPTR(new Uint8Array(clientKey[6].readByteArray(5)))
                        console.log("[+] SPEKE(pubKey) Length: "+pubLength+" Val: 0x"+bytes2hex(new Uint8Array(p2.readByteArray(pubLength))))
                    }
                })


                var speke_utility_createContexts = Module.findExportByName("libspekexp.so", "speke_utility_createContexts")
                console.log("[+] speke_utility_createContexts is: "+speke_utility_createContexts)
                var  hu_ECCParamsCreate = Module.findExportByName("libspekexp.so", " hu_ECCParamsCreate")
                console.log("[+] hu_ECCParamsCreate is: "+ hu_ECCParamsCreate)
                var  hu_ECSPEKEKeyGet = Module.findExportByName("libspekexp.so", " hu_ECSPEKEKeyGet")
                console.log("[+] hu_ECSPEKEKeyGet is: "+ hu_ECSPEKEKeyGet)
                var  hu_ECCKeyGet = Module.findExportByName("libspekexp.so", " hu_ECCKeyGet")
                console.log("[+] hu_ECCKeyGet is: "+ hu_ECCKeyGet)
                var  speke_ecc_generateClientKeys = Module.findExportByName("libspekexp.so", " speke_ecc_generateClientKeys")
                console.log("[+] speke_ecc_generateClientKeys is: "+ speke_ecc_generateClientKeys)
                var  speke_registry_generateClientKeys = Module.findExportByName("libspekexp.so", " speke_registry_generateClientKeys")
                console.log("[+] speke_registry_generateClientKeys is: "+ speke_registry_generateClientKeys)
                var  speke_ecc_generateSharedKey = Module.findExportByName("libspekexp.so", " speke_ecc_generateSharedKey")
                console.log("[+] speke_ecc_generateSharedKey is: "+ speke_ecc_generateSharedKey)
                var  _set_fixed_csr = Module.findExportByName("libspekexp.so", " _set_fixed_csr")
                console.log("[+] _set_fixed_csr is: "+ _set_fixed_csr)
                var  hu_ECSPEKEKeyGen = Module.findExportByName("libspekexp.so", " hu_ECSPEKEKeyGen")
                console.log("[+] hu_ECSPEKEKeyGen is: "+ hu_ECSPEKEKeyGen)


                // speke_utility_createContexts(&local_a0,&local_98);
                var createContexts = new Array()
                Interceptor.attach(speke_utility_createContexts, {
                    onEnter: function (args) {
                        console.log("[*] HIT speke_utility_createContexts")
                        for (var i=0; i<2; ++i) {
                            createContexts.push(args[i])
                            console.log("  [**] speke_utility_createContexts ARGS["+i+"]: 0x"+bytes2hex(new Uint8Array(args[i].readByteArray(32))))
                        }
                    },
                    onLeave: function (retval) {
                        console.log('[**] speke_utility_createContexts RET: '+JSON.stringify(retval))
                        for (var i=0; i<2; ++i) {
                            if (bytes2hex(new Uint8Array(createContexts[i].readByteArray(2))) != "0000") {
                                var p1 = edianPTR(new Uint8Array(createContexts[i].readByteArray(5)))
                                console.log("  [**] speke_utility_createContexts RET ARGS["+i+"]: 0x"+bytes2hex(new Uint8Array(p1.readByteArray(32))))
                            } else {
                                console.log("  [**] speke_utility_createContexts RET ARGS["+i+"]: 0x"+bytes2hex(new Uint8Array(createContexts[i].readByteArray(32))))
                            }
                            
                        }
                    }
                })
            }
        });
    }
},0);
