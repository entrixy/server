<?php
/* Перевод сайта: [английская строка => перевод]. Основной язык — английский. */
return [
    'Guide' => 'Guía',
    'App' => 'App',
    'Install the app' => 'Instalar la app',
    'Accept' => 'Aceptar',
    'Time' => 'Hora',
    'Security' => 'Seguridad',
    '. The' => '. El',
    'Open' => 'Abra',
    'and' => 'y',
    'QR code' => 'Código QR',
    'Link' => 'Enlace',
    'Text' => 'Texto',
    'OR' => 'O',
    'AND' => 'Y',
    'The' => 'El directorio',
    'Copy' => 'Copia',
    'Access request — Entrixy' => 'Solicitud de acceso — Entrixy',
    'A service is asking for access to your barrier. Decide yourself what to grant and take it back at any time.' => 'Un servicio pide acceso a su barrera. Usted decide qué conceder y lo retira cuando quiera.',
    'Access to your barrier' => 'Acceso a su barrera',
    'You decide what to grant, see every opening in the log and take access back in one tap.' => 'Usted decide qué conceder, ve cada apertura en el registro y retira el acceso con un toque.',
    'This company is asking for access to your barrier so that its employee can drive in on the day of the visit. Access is granted to the company, not to a particular person, and every opening is recorded in your log with the name of whoever pressed the button.' => 'Esta empresa pide acceso a su barrera para que su empleado pueda entrar el día de la visita. El acceso se concede a la empresa, no a una persona concreta, y cada apertura queda en su registro con el nombre de quien la pulsó.',
    'Install the app and add your barrier — it takes a couple of minutes.' => 'Instale la aplicación y añada su barrera: son un par de minutos.',
    'Grant access: the company will already be waiting in the list, nothing to copy or forward.' => 'Conceda el acceso: la empresa ya estará esperando en la lista, no hay que copiar ni reenviar nada.',
    'Take it back whenever you want. The company cannot pass the access on to anyone else.' => 'Retírelo cuando quiera. La empresa no puede pasar este acceso a nadie más.',
    'Your barrier has to open on a call from your number, and your phone has to stay online — the app dials for you at the moment of the request. If your barrier has an Entrixy controller, the phone is not needed at all.' => 'Su barrera debe abrirse con una llamada desde su número y su teléfono debe seguir en línea: la aplicación llama por usted en el momento de la solicitud. Si la barrera tiene un controlador Entrixy, el teléfono no hace falta.',
    'This request has expired. Ask the company for a new link — it takes them one click.' => 'Esta solicitud ha caducado. Pida a la empresa un enlace nuevo: para ellos es un clic.',
    'This link is not valid. Check that the address was scanned in full, or ask the company for a new one.' => 'Este enlace no es válido. Compruebe que la dirección se escaneó entera o pida otra a la empresa.',
    'State' => 'Estado',
    'Logo' => 'Logotipo',
    'domain not confirmed' => 'dominio no confirmado',
    'Android app' => 'Aplicación para Android',
    'guide' => 'guía',
    '.
        Do you manufacture hardware?' => '.
        ¿Fabricas equipos?',
    'app' => 'aplicación',
    'server' => 'servidor',
    'to your' => 'a tu',
    'Compute' => 'Calcula',
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
    'objects' => 'objetos',
    'Open in the app' => 'Abrir en la aplicación',
    'with its own' => 'con su propia',
    'Code' => 'Código',
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
    'The server' => 'El servidor',
    'without' => 'sin',
    'with' => 'con',
    'every' => 'cada',
    'With' => 'Con',
    'instead of' => 'en lugar de',
    'Check' => 'Comprobación',
    'empty' => 'vacío',
    'Guest' => 'Invitado',
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
    'On' => 'Activada',
    'Off' => 'Desactivada',
    'or' => 'o',
    'Bistable mode: the controller remembers the current position (open or closed) and
toggles it on every activation. The position is visible on the object icon in the app,
to owner and guest alike. The pin for the Close command is set below, in the Pins section.' => 'Modo biestable: el controlador recuerda la posición actual (abierto o cerrado) y
la conmuta en cada activación. La posición se ve en el icono del objeto en la aplicación,
tanto para el propietario como para el invitado. El pin para la orden Cerrar se define más abajo, en el apartado Pines.',
    'Language' => 'Idioma',
    'Config' => 'Configuración',
    'or the' => 'o en el',
    'Name' => 'Nombre',
    'Type' => 'Tipo',
    'Access' => 'Acceso',
    'Everyone' => 'Para todos',
    'active' => 'activo',
    '<div class="pm-row"><b>A 30 A relay is on the board</b>, controlled from <code>GPIO16</code>. <code>NO</code>+<code>COM</code> go to the Open terminals.</div>
           <div class="pm-row"><b>Power</b>: straight from the <b>mains</b> to the AC terminals — the power supply is built into the board.</div>
           <div class="pm-row"><b>Uploading the program</b>: a USB-UART programmer on the <code>TX/RX/GND</code> pins. <b>Flash the board DISCONNECTED from the mains</b> — powered from the programmer only.</div>' => '<div class="pm-row"><b>En la placa hay un relé de 30 A</b>, controlado desde <code>GPIO16</code>. <code>NO</code>+<code>COM</code> a los bornes Open.</div>
           <div class="pm-row"><b>Alimentación</b>: directamente de la <b>red</b> a los bornes AC: la fuente va montada en la placa.</div>
           <div class="pm-row"><b>Carga del programa</b>: programador USB-UART en los pines <code>TX/RX/GND</code>. <b>Graba la placa DESCONECTADA de la red</b>: alimentada solo desde el programador.</div>',
    '<div class="pm-row"><b>The relay control input</b> → <code>GPIO26</code>. The dry contact <code>O</code>/<code>I</code> on the terminals goes to Open.</div>
           <div class="pm-row"><b>Power</b>: AC 110–240 V or DC 24–240 V to the terminals.</div>
           <div class="pm-row"><b>Uploading the program</b>: there is no external USB. Open the case and connect a USB-UART adapter to the ESP32\'s UART pads (<code>3V3, GND, TX, RX</code>; <code>IO0</code> to ground to enter the bootloader). The case must be <b>disconnected from the mains</b>.</div>' => '<div class="pm-row"><b>La entrada de control del relé</b> → <code>GPIO26</code>. El contacto seco <code>O</code>/<code>I</code> de los bornes va a Abrir.</div>
           <div class="pm-row"><b>Alimentación</b>: AC 110–240 V o DC 24–240 V a los bornes.</div>
           <div class="pm-row"><b>Carga del programa</b>: no hay USB externo. Abre la carcasa y conéctate con un adaptador USB-UART a los pads UART del ESP32 (<code>3V3, GND, TX, RX</code>; <code>IO0</code> a masa para entrar en el bootloader). La carcasa debe estar <b>sin tensión de red</b>.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO16</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB or to the <code>5V</code>/<code>VIN</code> pin. The relay module takes its own <code>VCC</code>.</div>
           <div class="pm-row"><b>Uploading the program</b>: the board has USB and a converter on it — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>La entrada de control del relé</b> → pin <code>GPIO16</code> (se puede cambiar en el formulario de abajo).</div>
           <div class="pm-row"><b>Alimentación</b>: 5 V por USB o al pin <code>5V</code>/<code>VIN</code>. El módulo de relé lleva su propio <code>VCC</code>.</div>
           <div class="pm-row"><b>Carga del programa</b>: la placa tiene USB y convertidor: el programa se sube <b>directamente desde el navegador</b>, no hace falta programador.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO16</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V to <code>5V</code> or 3.3 V to <code>3V3</code>, soldered. The relay module takes its own <code>VCC</code>.</div>
           <div class="pm-row"><b>Uploading the program</b>: a bare module has no USB — drop it into a programmer and upload through the programmer\'s micro-USB. Only power and the relay are soldered to the module itself (do not forget the common ground, GND).</div>' => '<div class="pm-row"><b>La entrada de control del relé</b> → pin <code>GPIO16</code> (se puede cambiar en el formulario de abajo).</div>
           <div class="pm-row"><b>Alimentación</b>: 5 V a <code>5V</code> o 3,3 V a <code>3V3</code>, soldados. El módulo de relé lleva su propio <code>VCC</code>.</div>
           <div class="pm-row"><b>Carga del programa</b>: un módulo desnudo no tiene USB: encájalo en un programador y sube el programa por su micro-USB. Al módulo solo se le sueldan la alimentación y el relé (no olvides la masa común, GND).</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO3</code> (you can change it in the form).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB-C or 3.3 V to the <code>3V3</code> pin.</div>
           <div class="pm-row"><b>Uploading the program</b>: the board has USB-C — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>La entrada de control del relé</b> → pin <code>GPIO3</code> (se puede cambiar en el formulario).</div>
           <div class="pm-row"><b>Alimentación</b>: 5 V por USB-C o 3,3 V al pin <code>3V3</code>.</div>
           <div class="pm-row"><b>Carga del programa</b>: la placa tiene USB-C: el programa se sube <b>directamente desde el navegador</b>, no hace falta programador.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO4</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V / 3.3 V, soldered to the module\'s pins.</div>
           <div class="pm-row"><b>Uploading the program</b>: a bare module goes into a programmer — you do not solder USB to it. Power and the relay are soldered.</div>' => '<div class="pm-row"><b>La entrada de control del relé</b> → pin <code>GPIO4</code> (se puede cambiar en el formulario de abajo).</div>
           <div class="pm-row"><b>Alimentación</b>: 5 V / 3,3 V, soldados a los pines del módulo.</div>
           <div class="pm-row"><b>Carga del programa</b>: un módulo desnudo va al programador; el USB no se le suelda. La alimentación y el relé, soldados.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO4</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB or to the <code>5V</code>/<code>VIN</code> pin.</div>
           <div class="pm-row"><b>Uploading the program</b>: USB is on board — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>La entrada de control del relé</b> → pin <code>GPIO4</code> (se puede cambiar en el formulario de abajo).</div>
           <div class="pm-row"><b>Alimentación</b>: 5 V por USB o al pin <code>5V</code>/<code>VIN</code>.</div>
           <div class="pm-row"><b>Carga del programa</b>: el USB está a bordo: el programa se sube <b>directamente desde el navegador</b>, no hace falta programador.</div>',
    '<div class="pm-row"><b>The relay is already on the board</b>, controlled from <code>GPIO16</code>. Its <code>NO</code>+<code>COM</code> output goes to the drive\'s Open terminals.</div>
           <div class="pm-row"><b>Power</b>: 5 V over micro-USB, or 7–30 V to the power terminals.</div>
           <div class="pm-row"><b>Uploading the program</b>: micro-USB here is power only (there is no UART) — hook a USB-UART programmer to the <code>TX/RX/GND</code> pins and pull <code>IO0</code> to ground as you power it up.</div>' => '<div class="pm-row"><b>El relé ya está en la placa</b>, controlado desde <code>GPIO16</code>. La salida <code>NO</code>+<code>COM</code> va a los bornes Open del motor.</div>
           <div class="pm-row"><b>Alimentación</b>: 5 V por micro-USB o 7–30 V a los bornes de alimentación.</div>
           <div class="pm-row"><b>Carga del programa</b>: aquí el micro-USB es solo alimentación (no hay UART): conecta un programador USB-UART a los pines <code>TX/RX/GND</code> y lleva <code>IO0</code> a masa al encender.</div>',
    '<div class="pm-row">The pinout and flashing are the same as on the Plus 1: relay <code>GPIO26</code>, dry contact <code>O</code>/<code>I</code> to Open.</div>
           <div class="pm-row"><b>Power</b>: AC 110–240 V.</div>
           <div class="pm-row"><b>Uploading the program</b>: open the case, USB-UART to the ESP32\'s UART pads (<code>3V3/GND/TX/RX</code>, <code>IO0</code> to ground). The power-metering chip is unused by the Entrixy firmware. Disconnect it from the mains.</div>' => '<div class="pm-row">El pinout y la grabación son como en el Plus 1: relé <code>GPIO26</code>, contacto seco <code>O</code>/<code>I</code> a Abrir.</div>
           <div class="pm-row"><b>Alimentación</b>: AC 110–240 V.</div>
           <div class="pm-row"><b>Carga del programa</b>: abre la carcasa, USB-UART a los pads UART del ESP32 (<code>3V3/GND/TX/RX</code>, <code>IO0</code> a masa). El firmware de Entrixy no usa el chip de medida. Déjalo sin tensión de red.</div>',
    'account' => 'mi cuenta',
    'Two bytes of tag are deliberate: the state byte only drives the open/closed indicator
and grants no authority, while every extra byte of advertisement costs battery on every
wake-up. The tag guards against corruption on the air, not against a forger — 16 bits
fall to brute force in seconds. Nothing that decides access may travel this way.' => 'Dos bytes de etiqueta son a propósito: el byte de estado solo gobierna el indicador de abierto/cerrado y no concede ningún permiso, mientras que cada byte de más en el anuncio cuesta batería en cada despertar. La etiqueta protege de la corrupción en el aire, no de un falsificador: 16 bits caen en segundos. Nada que decida el acceso debe viajar por aquí.',
    'Domain' => 'Dominio',
    'expired' => 'caducado',
    'This link has already been used: access for this visit is granted. If it was you, the company is in your app under companies, together with the log of openings — you take the access back there at any time. If the link reached you by chance, ask the company for a new one: each link works once.' => 'Este enlace ya se ha usado: el acceso para esta visita está concedido. Si fuiste tú, la empresa está en tu aplicación, en la pestaña de empresas, junto con el registro de aperturas; allí retiras el acceso cuando quieras. Si el enlace te ha llegado por casualidad, pide uno nuevo a la empresa: cada enlace funciona una sola vez.',
    'Copy the link' => 'Copiar el enlace',
    'Be sure to check the domain %s against the site of the company you are about to grant access to.' => 'Compara sin falta el dominio %s con el sitio de la empresa a la que vas a conceder el acceso.',
    'This company has not confirmed a domain — there is only the name it entered. Grant access if you are sure who is asking.' => 'Esta empresa no ha confirmado un dominio: solo está el nombre indicado. Concede el acceso si sabes quién lo pide.',
    'The link is copied: after installation the app will pick it up itself, scanning again is not needed.' => 'El enlace está copiado: tras la instalación la aplicación lo recogerá sola, no hace falta volver a escanear.',
    'Powered by Entrixy' => 'Funciona con Entrixy',
];
