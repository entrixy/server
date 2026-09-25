<?php
/* Перевод сайта: [английская строка => перевод]. Основной язык — английский. */
return [
    'Guide' => 'Handbuch',
    'App' => 'App',
    'Install the app' => 'App installieren',
    'Accept' => 'Einverstanden',
    'Time' => 'Zeit',
    'Security' => 'Sicherheit',
    '. The' => '. Der',
    'Open' => 'Öffnen Sie',
    'and' => 'und',
    'QR code' => 'QR-Code',
    'Link' => 'Link',
    'Text' => 'Text',
    'OR' => 'ODER',
    'AND' => 'UND',
    'The' => 'Das Verzeichnis',
    'Copy' => 'Kopieren Sie',
    'Access request — Entrixy' => 'Zugangsanfrage — Entrixy',
    'A service is asking for access to your barrier. Decide yourself what to grant and take it back at any time.' => 'Ein Dienst bittet um Zugang zu Ihrer Schranke. Sie entscheiden, was Sie gewähren, und nehmen es jederzeit zurück.',
    'Access to your barrier' => 'Zugang zu Ihrer Schranke',
    'You decide what to grant, see every opening in the log and take access back in one tap.' => 'Sie entscheiden, was Sie gewähren, sehen jede Öffnung im Journal und nehmen den Zugang mit einem Tippen zurück.',
    'This company is asking for access to your barrier so that its employee can drive in on the day of the visit. Access is granted to the company, not to a particular person, and every opening is recorded in your log with the name of whoever pressed the button.' => 'Dieses Unternehmen bittet um Zugang zu Ihrer Schranke, damit sein Mitarbeiter am Tag des Besuchs einfahren kann. Der Zugang wird dem Unternehmen erteilt, nicht einer bestimmten Person, und jede Öffnung landet mit dem Namen des Auslösenden in Ihrem Journal.',
    'Install the app and add your barrier — it takes a couple of minutes.' => 'Installieren Sie die App und fügen Sie Ihre Schranke hinzu — ein paar Minuten.',
    'Grant access: the company will already be waiting in the list, nothing to copy or forward.' => 'Erteilen Sie den Zugang: Das Unternehmen wartet bereits in der Liste, nichts zu kopieren oder weiterzuleiten.',
    'Take it back whenever you want. The company cannot pass the access on to anyone else.' => 'Nehmen Sie ihn zurück, wann Sie wollen. Das Unternehmen kann diesen Zugang nicht weitergeben.',
    'Your barrier has to open on a call from your number, and your phone has to stay online — the app dials for you at the moment of the request. If your barrier has an Entrixy controller, the phone is not needed at all.' => 'Ihre Schranke muss sich auf einen Anruf von Ihrer Nummer öffnen und Ihr Telefon online bleiben — die App ruft im Moment der Anfrage für Sie an. Steht an der Schranke ein Entrixy-Controller, wird das Telefon gar nicht gebraucht.',
    'This request has expired. Ask the company for a new link — it takes them one click.' => 'Diese Anfrage ist abgelaufen. Bitten Sie das Unternehmen um einen neuen Link — für sie ein Klick.',
    'This link is not valid. Check that the address was scanned in full, or ask the company for a new one.' => 'Dieser Link ist ungültig. Prüfen Sie, ob die Adresse vollständig gescannt wurde, oder bitten Sie das Unternehmen um einen neuen.',
    'State' => 'Zustand',
    'Logo' => 'Logo',
    'domain not confirmed' => 'Domain nicht bestätigt',
    'Android app' => 'Android-App',
    'guide' => 'Anleitung',
    '.
        Do you manufacture hardware?' => '.
        Stellen Sie Technik her?',
    'app' => 'App',
    'server' => 'Server',
    'to your' => 'an Ihre',
    'Compute' => 'Berechnen Sie',
    'POST &lt;your webhook_url&gt;
Content-Type: application/json

{
  "action":    "open",
  "object_id": 42,
  "timestamp": 1750000000,
  "nonce":     "0011223344556677",
  "signature": "9d7b58066094fa88..."
}' => 'POST &lt;your webhook_url&gt;
Content-Type: application/json

{
  "action":    "open",
  "object_id": 42,
  "timestamp": 1750000000,
  "nonce":     "0011223344556677",
  "signature": "9d7b58066094fa88..."
}',
    'objects' => 'Objekte',
    'Open in the app' => 'In der App öffnen',
    'with its own' => 'mit seinem eigenen',
    'Code' => 'Code',
    'offset  size  field
[0..1]   2    Company ID = E0 00
[2..5]   4    device_id            (LE)
[6..9]   4    counter              (LE, monotonic, anti-replay, survives deep sleep)
[10..17] 8    auth_hmac            = HMAC(owner_secret, mac_in)[0..7]
[18]     1    sleep_interval_s     (plaintext)
[19..22] 4    opts_cipher          (battery, status, fw, hw — encrypted)' => 'offset  size  field
[0..1]   2    Company ID = E0 00
[2..5]   4    device_id            (LE)
[6..9]   4    counter              (LE, monotonic, anti-replay, survives deep sleep)
[10..17] 8    auth_hmac            = HMAC(owner_secret, mac_in)[0..7]
[18]     1    sleep_interval_s     (plaintext)
[19..22] 4    opts_cipher          (battery, status, fw, hw — encrypted)',
    'K_state = HKDF-SHA256(salt=null, ikm=owner_secret, info="ble-state-v1", L=16)
[..21] state_enc = state_byte XOR K_state[counter &amp; 15]     // bit0: 1=open, 0=closed
[22..23] state_mac = HMAC-SHA256(K_state, counter(4B LE) || state_enc)[0..1]   // 2 bytes' => 'K_state = HKDF-SHA256(salt=null, ikm=owner_secret, info="ble-state-v1", L=16)
[..21] state_enc = state_byte XOR K_state[counter &amp; 15]     // bit0: 1=open, 0=closed
[22..23] state_mac = HMAC-SHA256(K_state, counter(4B LE) || state_enc)[0..1]   // 2 bytes',
    'The server' => 'Der Server',
    'without' => 'ohne',
    'with' => 'mit',
    'every' => 'alle',
    'With' => 'Mit',
    'instead of' => 'statt',
    'Check' => 'Prüfung',
    'empty' => 'leer',
    'Guest' => 'Gast',
    '→ device_hello
{ "type":"device_hello",
  "device_key":    "&lt;32 hex&gt;",
  "device_secret": "&lt;32 hex&gt;",
  "e2ee":          true|false }        // whether a valid ownerSecret exists (§5)' => '→ device_hello
{ "type":"device_hello",
  "device_key":    "&lt;32 hex&gt;",
  "device_secret": "&lt;32 hex&gt;",
  "e2ee":          true|false }        // whether a valid ownerSecret exists (§5)',
    '❮&nbsp; device_ok  { "type":"device_ok", "hb_interval":300 }   // success; hb_interval in s (10..3600)
← error      { "type":"error", "reason":"auth" }         // failure → the server closes' => '❮&nbsp; device_ok  { "type":"device_ok", "hb_interval":300 }   // success; hb_interval in s (10..3600)
← error      { "type":"error", "reason":"auth" }         // failure → the server closes',
    '❮&nbsp; device_command
{ "type":"device_command", "action":"open", "command_id":"&lt;id&gt;", "number_id":&lt;n&gt; }
  // action:"close" — for a bistable drive' => '❮&nbsp; device_command
{ "type":"device_command", "action":"open", "command_id":"&lt;id&gt;", "number_id":&lt;n&gt; }
  // action:"close" — for a bistable drive',
    'PROVISION &lt;64 hex&gt;   → store the ownerSecret in NVS, return the fingerprint
WIPE                  → erase it (basic mode)
STATUS                → show the fingerprint
fingerprint = HMAC-SHA256(ownerSecret, "fp")[0..3]  (hex)' => 'PROVISION &lt;64 hex&gt;   → store the ownerSecret in NVS, return the fingerprint
WIPE                  → erase it (basic mode)
STATUS                → show the fingerprint
fingerprint = HMAC-SHA256(ownerSecret, "fp")[0..3]  (hex)',
    'token (3B) = [guest_did 2B LE][perms 1B]                      // a capability, no TTL
owner_sig  = HMAC-SHA256(ownerSecret, token)[0..15]
guest_key  = HKDF-SHA256(salt=null, ikm=ownerSecret, info="guest"||guest_did(2B LE), L=32)
proof      = HMAC-SHA256(guest_key, nonce)[0..15]' => 'token (3B) = [guest_did 2B LE][perms 1B]                      // a capability, no TTL
owner_sig  = HMAC-SHA256(ownerSecret, token)[0..15]
guest_key  = HKDF-SHA256(salt=null, ikm=ownerSecret, info="guest"||guest_did(2B LE), L=32)
proof      = HMAC-SHA256(guest_key, nonce)[0..15]',
    'OK' => 'OK',
    'On' => 'Ein',
    'Off' => 'Aus',
    'or' => 'oder',
    'Bistable mode: the controller remembers the current position (open or closed) and
toggles it on every activation. The position is visible on the object icon in the app,
to owner and guest alike. The pin for the Close command is set below, in the Pins section.' => 'Bistabiler Modus: Der Controller merkt sich die aktuelle Position (offen oder geschlossen) und
schaltet sie bei jeder Auslösung um. Die Position ist am Objektsymbol in der App zu sehen,
für Besitzer wie für Gast. Der Pin für den Befehl Schließen wird unten im Abschnitt Pins festgelegt.',
    'Language' => 'Sprache',
    'Config' => 'Konfiguration',
    'or the' => 'oder im',
    'Name' => 'Name',
    'Type' => 'Typ',
    'Access' => 'Zugang',
    'Everyone' => 'Für alle',
    'active' => 'aktiv',
    '<div class="pm-row"><b>A 30 A relay is on the board</b>, controlled from <code>GPIO16</code>. <code>NO</code>+<code>COM</code> go to the Open terminals.</div>
           <div class="pm-row"><b>Power</b>: straight from the <b>mains</b> to the AC terminals — the power supply is built into the board.</div>
           <div class="pm-row"><b>Uploading the program</b>: a USB-UART programmer on the <code>TX/RX/GND</code> pins. <b>Flash the board DISCONNECTED from the mains</b> — powered from the programmer only.</div>' => '<div class="pm-row"><b>Ein 30-A-Relais sitzt auf der Platine</b>, gesteuert über <code>GPIO16</code>. <code>NO</code>+<code>COM</code> an die Open-Klemmen.</div>
           <div class="pm-row"><b>Stromversorgung</b>: direkt aus dem <b>Netz</b> an die AC-Klemmen — das Netzteil sitzt auf der Platine.</div>
           <div class="pm-row"><b>Programm aufspielen</b>: USB-UART-Programmiergerät an die Pins <code>TX/RX/GND</code>. <b>Flashen Sie die Platine VOM NETZ GETRENNT</b> — versorgt wird sie nur vom Programmiergerät.</div>',
    '<div class="pm-row"><b>The relay control input</b> → <code>GPIO26</code>. The dry contact <code>O</code>/<code>I</code> on the terminals goes to Open.</div>
           <div class="pm-row"><b>Power</b>: AC 110–240 V or DC 24–240 V to the terminals.</div>
           <div class="pm-row"><b>Uploading the program</b>: there is no external USB. Open the case and connect a USB-UART adapter to the ESP32\'s UART pads (<code>3V3, GND, TX, RX</code>; <code>IO0</code> to ground to enter the bootloader). The case must be <b>disconnected from the mains</b>.</div>' => '<div class="pm-row"><b>Der Steuereingang des Relais</b> → <code>GPIO26</code>. Der potentialfreie Kontakt <code>O</code>/<code>I</code> an den Klemmen geht auf Öffnen.</div>
           <div class="pm-row"><b>Stromversorgung</b>: AC 110–240 V oder DC 24–240 V an die Klemmen.</div>
           <div class="pm-row"><b>Programm aufspielen</b>: Externes USB gibt es nicht. Öffnen Sie das Gehäuse und schließen Sie einen USB-UART-Adapter an die UART-Pads des ESP32 an (<code>3V3, GND, TX, RX</code>; <code>IO0</code> auf Masse, um in den Bootloader zu gelangen). Das Gehäuse muss <b>vom Netz getrennt</b> sein.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO16</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB or to the <code>5V</code>/<code>VIN</code> pin. The relay module takes its own <code>VCC</code>.</div>
           <div class="pm-row"><b>Uploading the program</b>: the board has USB and a converter on it — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>Der Steuereingang des Relais</b> → Pin <code>GPIO16</code> (unten im Formular änderbar).</div>
           <div class="pm-row"><b>Stromversorgung</b>: 5 V über USB oder an den Pin <code>5V</code>/<code>VIN</code>. Das Relaismodul bekommt sein eigenes <code>VCC</code>.</div>
           <div class="pm-row"><b>Programm aufspielen</b>: Die Platine hat USB und einen Wandler — das Programm wird <b>direkt aus dem Browser</b> aufgespielt, ein Programmiergerät ist nicht nötig.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO16</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V to <code>5V</code> or 3.3 V to <code>3V3</code>, soldered. The relay module takes its own <code>VCC</code>.</div>
           <div class="pm-row"><b>Uploading the program</b>: a bare module has no USB — drop it into a programmer and upload through the programmer\'s micro-USB. Only power and the relay are soldered to the module itself (do not forget the common ground, GND).</div>' => '<div class="pm-row"><b>Der Steuereingang des Relais</b> → Pin <code>GPIO16</code> (unten im Formular änderbar).</div>
           <div class="pm-row"><b>Stromversorgung</b>: 5 V an <code>5V</code> oder 3,3 V an <code>3V3</code> — gelötet. Das Relaismodul bekommt sein eigenes <code>VCC</code>.</div>
           <div class="pm-row"><b>Programm aufspielen</b>: Ein nacktes Modul hat kein USB — stecken Sie es in ein Programmiergerät und spielen Sie das Programm über dessen micro-USB auf. An das Modul selbst werden nur Versorgung und Relais gelötet (die gemeinsame Masse GND nicht vergessen).</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO3</code> (you can change it in the form).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB-C or 3.3 V to the <code>3V3</code> pin.</div>
           <div class="pm-row"><b>Uploading the program</b>: the board has USB-C — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>Der Steuereingang des Relais</b> → Pin <code>GPIO3</code> (im Formular änderbar).</div>
           <div class="pm-row"><b>Stromversorgung</b>: 5 V über USB-C oder 3,3 V an den Pin <code>3V3</code>.</div>
           <div class="pm-row"><b>Programm aufspielen</b>: Die Platine hat USB-C — das Programm wird <b>direkt aus dem Browser</b> aufgespielt, ein Programmiergerät ist nicht nötig.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO4</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V / 3.3 V, soldered to the module\'s pins.</div>
           <div class="pm-row"><b>Uploading the program</b>: a bare module goes into a programmer — you do not solder USB to it. Power and the relay are soldered.</div>' => '<div class="pm-row"><b>Der Steuereingang des Relais</b> → Pin <code>GPIO4</code> (unten im Formular änderbar).</div>
           <div class="pm-row"><b>Stromversorgung</b>: 5 V / 3,3 V — an die Pins des Moduls gelötet.</div>
           <div class="pm-row"><b>Programm aufspielen</b>: Ein nacktes Modul kommt ins Programmiergerät, USB wird nicht angelötet. Versorgung und Relais werden gelötet.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO4</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB or to the <code>5V</code>/<code>VIN</code> pin.</div>
           <div class="pm-row"><b>Uploading the program</b>: USB is on board — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>Der Steuereingang des Relais</b> → Pin <code>GPIO4</code> (unten im Formular änderbar).</div>
           <div class="pm-row"><b>Stromversorgung</b>: 5 V über USB oder an den Pin <code>5V</code>/<code>VIN</code>.</div>
           <div class="pm-row"><b>Programm aufspielen</b>: USB ist an Bord — das Programm wird <b>direkt aus dem Browser</b> aufgespielt, ein Programmiergerät ist nicht nötig.</div>',
    '<div class="pm-row"><b>The relay is already on the board</b>, controlled from <code>GPIO16</code>. Its <code>NO</code>+<code>COM</code> output goes to the drive\'s Open terminals.</div>
           <div class="pm-row"><b>Power</b>: 5 V over micro-USB, or 7–30 V to the power terminals.</div>
           <div class="pm-row"><b>Uploading the program</b>: micro-USB here is power only (there is no UART) — hook a USB-UART programmer to the <code>TX/RX/GND</code> pins and pull <code>IO0</code> to ground as you power it up.</div>' => '<div class="pm-row"><b>Das Relais sitzt schon auf der Platine</b>, gesteuert über <code>GPIO16</code>. Der Ausgang <code>NO</code>+<code>COM</code> geht an die Open-Klemmen des Antriebs.</div>
           <div class="pm-row"><b>Stromversorgung</b>: 5 V über micro-USB oder 7–30 V an die Versorgungsklemmen.</div>
           <div class="pm-row"><b>Programm aufspielen</b>: micro-USB dient hier nur der Versorgung (UART gibt es nicht) — schließen Sie ein USB-UART-Programmiergerät an die Pins <code>TX/RX/GND</code> an und legen Sie <code>IO0</code> beim Einschalten auf Masse.</div>',
    '<div class="pm-row">The pinout and flashing are the same as on the Plus 1: relay <code>GPIO26</code>, dry contact <code>O</code>/<code>I</code> to Open.</div>
           <div class="pm-row"><b>Power</b>: AC 110–240 V.</div>
           <div class="pm-row"><b>Uploading the program</b>: open the case, USB-UART to the ESP32\'s UART pads (<code>3V3/GND/TX/RX</code>, <code>IO0</code> to ground). The power-metering chip is unused by the Entrixy firmware. Disconnect it from the mains.</div>' => '<div class="pm-row">Pinbelegung und Flashen sind wie beim Plus 1: Relais <code>GPIO26</code>, potentialfreier Kontakt <code>O</code>/<code>I</code> auf Öffnen.</div>
           <div class="pm-row"><b>Stromversorgung</b>: AC 110–240 V.</div>
           <div class="pm-row"><b>Programm aufspielen</b>: Gehäuse öffnen, USB-UART an die UART-Pads des ESP32 (<code>3V3/GND/TX/RX</code>, <code>IO0</code> auf Masse). Den Messchip nutzt die Entrixy-Firmware nicht. Vom Netz trennen.</div>',
    'account' => 'Konto',
    'Two bytes of tag are deliberate: the state byte only drives the open/closed indicator
and grants no authority, while every extra byte of advertisement costs battery on every
wake-up. The tag guards against corruption on the air, not against a forger — 16 bits
fall to brute force in seconds. Nothing that decides access may travel this way.' => 'Zwei Byte Tag sind Absicht: Das Zustandsbyte steuert nur die Anzeige „offen/geschlossen“ und gewährt keine Rechte, während jedes zusätzliche Byte des Advertisements bei jedem Aufwachen Akku kostet. Das Tag schützt vor Verfälschung im Funk, nicht vor einem Fälscher — 16 Bit fallen in Sekunden. Nichts, was über Zugang entscheidet, darf diesen Weg nehmen.',
    'Domain' => 'Domain',
    'expired' => 'abgelaufen',
    'This link has already been used: access for this visit is granted. If it was you, the company is in your app under companies, together with the log of openings — you take the access back there at any time. If the link reached you by chance, ask the company for a new one: each link works once.' => 'Dieser Link wurde bereits verwendet: Der Zugang für diesen Besuch ist erteilt. Waren Sie es, steht das Unternehmen in Ihrer App unter «Unternehmen» samt Protokoll der Öffnungen — dort nehmen Sie den Zugang jederzeit zurück. Ist der Link zufällig bei Ihnen gelandet, bitten Sie das Unternehmen um einen neuen: Jeder Link funktioniert einmal.',
    'Copy the link' => 'Link kopieren',
    'Be sure to check the domain %s against the site of the company you are about to grant access to.' => 'Vergleichen Sie unbedingt die Domain %s mit der Website des Unternehmens, dem Sie den Zugang erteilen wollen.',
    'This company has not confirmed a domain — there is only the name it entered. Grant access if you are sure who is asking.' => 'Dieses Unternehmen hat keine Domain bestätigt — es gibt nur den angegebenen Namen. Erteilen Sie den Zugang, wenn Sie sicher sind, wer fragt.',
    'The link is copied: after installation the app will pick it up itself, scanning again is not needed.' => 'Der Link ist kopiert: Nach der Installation übernimmt ihn die App selbst, erneutes Scannen ist nicht nötig.',
    'Powered by Entrixy' => 'Läuft auf Entrixy',
];
