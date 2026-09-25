<?php
/* Перевод сайта: [английская строка => перевод]. Основной язык — английский. */
return [
    'Guide' => 'Guia',
    'App' => 'App',
    'Install the app' => 'Instalar o app',
    'Accept' => 'Aceitar',
    'Time' => 'Hora',
    'Security' => 'Segurança',
    '. The' => '. O',
    'Open' => 'Abra',
    'and' => 'e',
    'QR code' => 'Código QR',
    'Link' => 'Link',
    'Text' => 'Texto',
    'OR' => 'OU',
    'AND' => 'E',
    'The' => 'O diretório',
    'Copy' => 'Copie',
    'Access request — Entrixy' => 'Pedido de acesso — Entrixy',
    'A service is asking for access to your barrier. Decide yourself what to grant and take it back at any time.' => 'Um serviço pede acesso à sua cancela. Você decide o que conceder e retira quando quiser.',
    'Access to your barrier' => 'Acesso à sua cancela',
    'You decide what to grant, see every opening in the log and take access back in one tap.' => 'Você decide o que conceder, vê cada abertura no registo e retira o acesso com um toque.',
    'This company is asking for access to your barrier so that its employee can drive in on the day of the visit. Access is granted to the company, not to a particular person, and every opening is recorded in your log with the name of whoever pressed the button.' => 'Esta empresa pede acesso à sua cancela para que o seu funcionário possa entrar no dia da visita. O acesso é concedido à empresa, não a uma pessoa concreta, e cada abertura fica no seu registo com o nome de quem carregou.',
    'Install the app and add your barrier — it takes a couple of minutes.' => 'Instale a aplicação e adicione a sua cancela — são dois minutos.',
    'Grant access: the company will already be waiting in the list, nothing to copy or forward.' => 'Conceda o acesso: a empresa já estará à espera na lista, nada para copiar ou reenviar.',
    'Take it back whenever you want. The company cannot pass the access on to anyone else.' => 'Retire-o quando quiser. A empresa não pode passar este acesso a mais ninguém.',
    'Your barrier has to open on a call from your number, and your phone has to stay online — the app dials for you at the moment of the request. If your barrier has an Entrixy controller, the phone is not needed at all.' => 'A sua cancela tem de abrir com uma chamada do seu número e o seu telemóvel tem de ficar online: a aplicação liga por si no momento do pedido. Se a cancela tiver um controlador Entrixy, o telemóvel não é preciso.',
    'This request has expired. Ask the company for a new link — it takes them one click.' => 'Este pedido expirou. Peça à empresa uma ligação nova — para eles é um clique.',
    'This link is not valid. Check that the address was scanned in full, or ask the company for a new one.' => 'Esta ligação não é válida. Verifique se o endereço foi lido por inteiro ou peça uma nova à empresa.',
    'State' => 'Estado',
    'Logo' => 'Logótipo',
    'domain not confirmed' => 'domínio não confirmado',
    'Android app' => 'Aplicação Android',
    'guide' => 'guia',
    '.
        Do you manufacture hardware?' => '.
        Fabrica equipamento?',
    'app' => 'aplicação',
    'server' => 'servidor',
    'to your' => 'para o seu',
    'Compute' => 'Calcule',
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
    'Open in the app' => 'Abrir na aplicação',
    'with its own' => 'com a sua própria',
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
    'The server' => 'O servidor',
    'without' => 'sem',
    'with' => 'com',
    'every' => 'a cada',
    'With' => 'Com',
    'instead of' => 'em vez de',
    'Check' => 'Verificação',
    'empty' => 'vazio',
    'Guest' => 'Convidado',
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
    'On' => 'Ligada',
    'Off' => 'Desligada',
    'or' => 'ou',
    'Bistable mode: the controller remembers the current position (open or closed) and
toggles it on every activation. The position is visible on the object icon in the app,
to owner and guest alike. The pin for the Close command is set below, in the Pins section.' => 'Modo biestável: o controlador lembra-se da posição atual (aberto ou fechado) e
alterna-a em cada ativação. A posição vê-se no ícone do objeto na aplicação,
tanto para o proprietário como para o convidado. O pino do comando Fechar define-se mais abaixo, na secção Pinos.',
    'Language' => 'Idioma',
    'Config' => 'Configuração',
    'or the' => 'ou no',
    'Name' => 'Nome',
    'Type' => 'Tipo',
    'Access' => 'Acesso',
    'Everyone' => 'Para todos',
    'active' => 'ativo',
    '<div class="pm-row"><b>A 30 A relay is on the board</b>, controlled from <code>GPIO16</code>. <code>NO</code>+<code>COM</code> go to the Open terminals.</div>
           <div class="pm-row"><b>Power</b>: straight from the <b>mains</b> to the AC terminals — the power supply is built into the board.</div>
           <div class="pm-row"><b>Uploading the program</b>: a USB-UART programmer on the <code>TX/RX/GND</code> pins. <b>Flash the board DISCONNECTED from the mains</b> — powered from the programmer only.</div>' => '<div class="pm-row"><b>Há um relé de 30 A na placa</b>, comandado por <code>GPIO16</code>. <code>NO</code>+<code>COM</code> para os bornes Open.</div>
           <div class="pm-row"><b>Alimentação</b>: diretamente da <b>rede</b> para os bornes AC — a fonte está montada na placa.</div>
           <div class="pm-row"><b>Carregamento do programa</b>: programador USB-UART nos pinos <code>TX/RX/GND</code>. <b>Grave a placa DESLIGADA da rede</b> — alimentada apenas pelo programador.</div>',
    '<div class="pm-row"><b>The relay control input</b> → <code>GPIO26</code>. The dry contact <code>O</code>/<code>I</code> on the terminals goes to Open.</div>
           <div class="pm-row"><b>Power</b>: AC 110–240 V or DC 24–240 V to the terminals.</div>
           <div class="pm-row"><b>Uploading the program</b>: there is no external USB. Open the case and connect a USB-UART adapter to the ESP32\'s UART pads (<code>3V3, GND, TX, RX</code>; <code>IO0</code> to ground to enter the bootloader). The case must be <b>disconnected from the mains</b>.</div>' => '<div class="pm-row"><b>A entrada de comando do relé</b> → <code>GPIO26</code>. O contacto seco <code>O</code>/<code>I</code> dos bornes vai para Abrir.</div>
           <div class="pm-row"><b>Alimentação</b>: AC 110–240 V ou DC 24–240 V nos bornes.</div>
           <div class="pm-row"><b>Carregamento do programa</b>: não há USB externo. Abra a caixa e ligue um adaptador USB-UART aos pads UART do ESP32 (<code>3V3, GND, TX, RX</code>; <code>IO0</code> à massa para entrar no bootloader). A caixa tem de estar <b>sem tensão de rede</b>.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO16</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB or to the <code>5V</code>/<code>VIN</code> pin. The relay module takes its own <code>VCC</code>.</div>
           <div class="pm-row"><b>Uploading the program</b>: the board has USB and a converter on it — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>A entrada de comando do relé</b> → pino <code>GPIO16</code> (pode mudar-se no formulário abaixo).</div>
           <div class="pm-row"><b>Alimentação</b>: 5 V por USB ou no pino <code>5V</code>/<code>VIN</code>. O módulo de relé leva o seu próprio <code>VCC</code>.</div>
           <div class="pm-row"><b>Carregamento do programa</b>: a placa tem USB e conversor — o programa carrega-se <b>diretamente do navegador</b>, não é preciso programador.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO16</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V to <code>5V</code> or 3.3 V to <code>3V3</code>, soldered. The relay module takes its own <code>VCC</code>.</div>
           <div class="pm-row"><b>Uploading the program</b>: a bare module has no USB — drop it into a programmer and upload through the programmer\'s micro-USB. Only power and the relay are soldered to the module itself (do not forget the common ground, GND).</div>' => '<div class="pm-row"><b>A entrada de comando do relé</b> → pino <code>GPIO16</code> (pode mudar-se no formulário abaixo).</div>
           <div class="pm-row"><b>Alimentação</b>: 5 V em <code>5V</code> ou 3,3 V em <code>3V3</code>, soldados. O módulo de relé leva o seu próprio <code>VCC</code>.</div>
           <div class="pm-row"><b>Carregamento do programa</b>: um módulo nu não tem USB — encaixe-o num programador e carregue o programa pelo micro-USB deste. Ao módulo em si só se soldam a alimentação e o relé (não esqueça a massa comum, GND).</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO3</code> (you can change it in the form).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB-C or 3.3 V to the <code>3V3</code> pin.</div>
           <div class="pm-row"><b>Uploading the program</b>: the board has USB-C — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>A entrada de comando do relé</b> → pino <code>GPIO3</code> (pode mudar-se no formulário).</div>
           <div class="pm-row"><b>Alimentação</b>: 5 V por USB-C ou 3,3 V no pino <code>3V3</code>.</div>
           <div class="pm-row"><b>Carregamento do programa</b>: a placa tem USB-C — o programa carrega-se <b>diretamente do navegador</b>, não é preciso programador.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO4</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V / 3.3 V, soldered to the module\'s pins.</div>
           <div class="pm-row"><b>Uploading the program</b>: a bare module goes into a programmer — you do not solder USB to it. Power and the relay are soldered.</div>' => '<div class="pm-row"><b>A entrada de comando do relé</b> → pino <code>GPIO4</code> (pode mudar-se no formulário abaixo).</div>
           <div class="pm-row"><b>Alimentação</b>: 5 V / 3,3 V, soldados aos pinos do módulo.</div>
           <div class="pm-row"><b>Carregamento do programa</b>: um módulo nu vai para o programador; o USB não se lhe solda. A alimentação e o relé soldam-se.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO4</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB or to the <code>5V</code>/<code>VIN</code> pin.</div>
           <div class="pm-row"><b>Uploading the program</b>: USB is on board — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>A entrada de comando do relé</b> → pino <code>GPIO4</code> (pode mudar-se no formulário abaixo).</div>
           <div class="pm-row"><b>Alimentação</b>: 5 V por USB ou no pino <code>5V</code>/<code>VIN</code>.</div>
           <div class="pm-row"><b>Carregamento do programa</b>: o USB está a bordo — o programa carrega-se <b>diretamente do navegador</b>, não é preciso programador.</div>',
    '<div class="pm-row"><b>The relay is already on the board</b>, controlled from <code>GPIO16</code>. Its <code>NO</code>+<code>COM</code> output goes to the drive\'s Open terminals.</div>
           <div class="pm-row"><b>Power</b>: 5 V over micro-USB, or 7–30 V to the power terminals.</div>
           <div class="pm-row"><b>Uploading the program</b>: micro-USB here is power only (there is no UART) — hook a USB-UART programmer to the <code>TX/RX/GND</code> pins and pull <code>IO0</code> to ground as you power it up.</div>' => '<div class="pm-row"><b>O relé já está na placa</b>, comandado por <code>GPIO16</code>. A saída <code>NO</code>+<code>COM</code> vai para os bornes Open do motor.</div>
           <div class="pm-row"><b>Alimentação</b>: 5 V por micro-USB ou 7–30 V nos bornes de alimentação.</div>
           <div class="pm-row"><b>Carregamento do programa</b>: aqui o micro-USB é só alimentação (não há UART) — ligue um programador USB-UART aos pinos <code>TX/RX/GND</code> e ponha o <code>IO0</code> à massa ao ligar.</div>',
    '<div class="pm-row">The pinout and flashing are the same as on the Plus 1: relay <code>GPIO26</code>, dry contact <code>O</code>/<code>I</code> to Open.</div>
           <div class="pm-row"><b>Power</b>: AC 110–240 V.</div>
           <div class="pm-row"><b>Uploading the program</b>: open the case, USB-UART to the ESP32\'s UART pads (<code>3V3/GND/TX/RX</code>, <code>IO0</code> to ground). The power-metering chip is unused by the Entrixy firmware. Disconnect it from the mains.</div>' => '<div class="pm-row">A pinagem e a gravação são como no Plus 1: relé <code>GPIO26</code>, contacto seco <code>O</code>/<code>I</code> para Abrir.</div>
           <div class="pm-row"><b>Alimentação</b>: AC 110–240 V.</div>
           <div class="pm-row"><b>Carregamento do programa</b>: abra a caixa, USB-UART nos pads UART do ESP32 (<code>3V3/GND/TX/RX</code>, <code>IO0</code> à massa). O firmware do Entrixy não usa o chip de medição. Desligue da rede.</div>',
    'account' => 'a minha conta',
    'Two bytes of tag are deliberate: the state byte only drives the open/closed indicator
and grants no authority, while every extra byte of advertisement costs battery on every
wake-up. The tag guards against corruption on the air, not against a forger — 16 bits
fall to brute force in seconds. Nothing that decides access may travel this way.' => 'Dois bytes de etiqueta são de propósito: o byte de estado só governa o indicador aberto/fechado e não concede qualquer direito, enquanto cada byte a mais do anúncio custa bateria em cada despertar. A etiqueta protege da corrupção no ar, não de um falsificador — 16 bits caem em segundos. Nada que decida o acesso deve viajar por aqui.',
    'Domain' => 'Domínio',
    'expired' => 'expirado',
    'This link has already been used: access for this visit is granted. If it was you, the company is in your app under companies, together with the log of openings — you take the access back there at any time. If the link reached you by chance, ask the company for a new one: each link works once.' => 'Esta ligação já foi usada: o acesso para esta visita está concedido. Se foi você, a empresa está na sua aplicação, no separador das empresas, juntamente com o registo de aberturas — é aí que retira o acesso quando quiser. Se a ligação lhe chegou por acaso, peça uma nova à empresa: cada ligação funciona uma só vez.',
    'Copy the link' => 'Copiar a ligação',
    'Be sure to check the domain %s against the site of the company you are about to grant access to.' => 'Compare sem falta o domínio %s com o site da empresa a quem vai conceder o acesso.',
    'This company has not confirmed a domain — there is only the name it entered. Grant access if you are sure who is asking.' => 'Esta empresa não confirmou um domínio — há apenas o nome indicado. Conceda o acesso se souber quem está a pedir.',
    'The link is copied: after installation the app will pick it up itself, scanning again is not needed.' => 'A ligação está copiada: depois da instalação a aplicação vai buscá-la sozinha, não é preciso digitalizar de novo.',
    'Powered by Entrixy' => 'Funciona com Entrixy',
];
