// @license magnet:?xt=urn:btih:1f739d935676111cfff4b4693e3816e664797050&dn=gpl-3.0.txt GPL-v3-or-Later
window.onload = started;

var req;
var timer_disabled=0;

function loadXMLDoc(url) {
	req = false;
	if (window.XMLHttpRequest && !(window.ActiveXObject)) {
		try {
			req = new XMLHttpRequest();
		} catch (e) {
			req = false;
		}
	} else if (window.ActiveXObject) {
		try {
			req = new ActiveXObject("Msxml2.XMLHTTP");
		} catch (e) {
			try {
				req = new ActiveXObject("Microsoft.XMLHTTP");
			} catch (e) {
				req = false;
			}
		}
	}
	if (req) {
		req.overrideMimeType("text/xml");
		req.onreadystatechange = processReqChange;
		req.open("GET", url, true);
		req.send("");
	}
}

function substringTillClosing(str,fromIndex){
	var opentags=0;
	var i=fromIndex;
	for(;i<str.length-1;i++){
		if(str.charAt(i)=="<" && str.charAt(i+1)=="/"){
			opentags--;
		}else if(str.charAt(i)=="<"){
			opentags++;
		}else if(str.charAt(i)=="/" && str.charAt(i+1)==">"){
			opentags--;
		}
		if(opentags==-1){
			return str.substring(str.indexOf(">",fromIndex)+1,i-1);
		}
	}
}

function processReqChange() {
	if (timer_disabled) return;
	if (req.readyState == 4) {
		if (req.status == 200) {
			if(req.responseText.indexOf("infoContent")==-1){
				timer_disabled=1;
				window.location.reload();
			}else{
				document.getElementById('infoContent').innerHTML=substringTillClosing(req.responseText,req.responseText.indexOf("id=\"infoContent\""))
			}
		}else if(req.status==500 || req.status==404){
			timer_disabled=1;
			window.location.reload();
		}
		setTimeout(sendRequest, 2000);
	}
}

function sendRequest() {
	loadXMLDoc(document.location.href);
}

function started() {
	setTimeout(sendRequest, 2000);
}
// @license-end