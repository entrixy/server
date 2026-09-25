<?php
/* Перевод сайта: [английская строка => перевод]. Основной язык — английский. */
return [
    'Guide' => 'Guide',
    'App' => 'Application',
    'Install the app' => 'Installer l\'application',
    'Accept' => 'Accepter',
    'Time' => 'Heure',
    'Security' => 'Sécurité',
    '. The' => '. La puce',
    'Open' => 'Ouvrez',
    'and' => 'et',
    'QR code' => 'QR code',
    'Link' => 'Lien',
    'Text' => 'Texte',
    'OR' => 'OU',
    'AND' => 'ET',
    'The' => 'Le répertoire',
    'Copy' => 'Copiez',
    'Access request — Entrixy' => 'Demande d\'accès — Entrixy',
    'A service is asking for access to your barrier. Decide yourself what to grant and take it back at any time.' => 'Un service demande l\'accès à votre barrière. Vous décidez de ce que vous accordez et le retirez quand vous voulez.',
    'Access to your barrier' => 'Accès à votre barrière',
    'You decide what to grant, see every opening in the log and take access back in one tap.' => 'Vous décidez de ce que vous accordez, voyez chaque ouverture dans le journal et retirez l\'accès d\'une pression.',
    'This company is asking for access to your barrier so that its employee can drive in on the day of the visit. Access is granted to the company, not to a particular person, and every opening is recorded in your log with the name of whoever pressed the button.' => 'Cette entreprise demande l\'accès à votre barrière pour que son employé puisse entrer le jour de la visite. L\'accès est accordé à l\'entreprise, non à une personne précise, et chaque ouverture figure dans votre journal avec le nom de celui qui a appuyé.',
    'Install the app and add your barrier — it takes a couple of minutes.' => 'Installez l\'application et ajoutez votre barrière — deux minutes.',
    'Grant access: the company will already be waiting in the list, nothing to copy or forward.' => 'Accordez l\'accès : l\'entreprise attend déjà dans la liste, rien à copier ni à transférer.',
    'Take it back whenever you want. The company cannot pass the access on to anyone else.' => 'Retirez-le quand vous voulez. L\'entreprise ne peut transmettre cet accès à personne.',
    'Your barrier has to open on a call from your number, and your phone has to stay online — the app dials for you at the moment of the request. If your barrier has an Entrixy controller, the phone is not needed at all.' => 'Votre barrière doit s\'ouvrir sur un appel depuis votre numéro et votre téléphone rester en ligne : l\'application appelle pour vous au moment de la demande. Si la barrière a un contrôleur Entrixy, le téléphone n\'est pas nécessaire.',
    'This request has expired. Ask the company for a new link — it takes them one click.' => 'Cette demande a expiré. Demandez un nouveau lien à l\'entreprise — c\'est un clic pour eux.',
    'This link is not valid. Check that the address was scanned in full, or ask the company for a new one.' => 'Ce lien n\'est pas valide. Vérifiez que l\'adresse a été scannée en entier ou demandez-en un nouveau à l\'entreprise.',
    'State' => 'État',
    'Logo' => 'Logo',
    'domain not confirmed' => 'domaine non confirmé',
    'Android app' => 'Application Android',
    'guide' => 'guide',
    '.
        Do you manufacture hardware?' => '.
        Vous fabriquez du matériel ?',
    'app' => 'application',
    'server' => 'serveur',
    'to your' => 'vers votre',
    'Compute' => 'Calculez',
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
    'objects' => 'objets',
    'Open in the app' => 'Ouvrir dans l\'application',
    'with its own' => 'avec sa propre',
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
    'The server' => 'Le serveur',
    'without' => 'sans',
    'with' => 'avec',
    'every' => 'toutes les',
    'With' => 'Avec',
    'instead of' => 'au lieu de',
    'Check' => 'Vérification',
    'empty' => 'vide',
    'Guest' => 'Invité',
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
    'On' => 'Activée',
    'Off' => 'Désactivée',
    'or' => 'ou',
    'Bistable mode: the controller remembers the current position (open or closed) and
toggles it on every activation. The position is visible on the object icon in the app,
to owner and guest alike. The pin for the Close command is set below, in the Pins section.' => 'Mode bistable : le contrôleur mémorise la position courante (ouvert ou fermé) et
la bascule à chaque activation. La position est visible sur l\'icône de l\'objet dans l\'application,
pour le propriétaire comme pour l\'invité. La broche de la commande Fermer se règle plus bas, dans la section Broches.',
    'Language' => 'Langue',
    'Config' => 'Configuration',
    'or the' => 'ou dans le',
    'Name' => 'Nom',
    'Type' => 'Type',
    'Access' => 'Accès',
    'Everyone' => 'Pour tous',
    'active' => 'actif',
    '<div class="pm-row"><b>A 30 A relay is on the board</b>, controlled from <code>GPIO16</code>. <code>NO</code>+<code>COM</code> go to the Open terminals.</div>
           <div class="pm-row"><b>Power</b>: straight from the <b>mains</b> to the AC terminals — the power supply is built into the board.</div>
           <div class="pm-row"><b>Uploading the program</b>: a USB-UART programmer on the <code>TX/RX/GND</code> pins. <b>Flash the board DISCONNECTED from the mains</b> — powered from the programmer only.</div>' => '<div class="pm-row"><b>Un relais de 30 A est sur la carte</b>, commandé par <code>GPIO16</code>. <code>NO</code>+<code>COM</code> vers les bornes Open.</div>
           <div class="pm-row"><b>Alimentation</b> : directement sur le <b>secteur</b>, aux bornes AC — l\'alimentation est intégrée à la carte.</div>
           <div class="pm-row"><b>Téléversement du programme</b> : programmateur USB-UART sur les broches <code>TX/RX/GND</code>. <b>Flashez la carte DÉBRANCHÉE du secteur</b> — alimentée uniquement par le programmateur.</div>',
    '<div class="pm-row"><b>The relay control input</b> → <code>GPIO26</code>. The dry contact <code>O</code>/<code>I</code> on the terminals goes to Open.</div>
           <div class="pm-row"><b>Power</b>: AC 110–240 V or DC 24–240 V to the terminals.</div>
           <div class="pm-row"><b>Uploading the program</b>: there is no external USB. Open the case and connect a USB-UART adapter to the ESP32\'s UART pads (<code>3V3, GND, TX, RX</code>; <code>IO0</code> to ground to enter the bootloader). The case must be <b>disconnected from the mains</b>.</div>' => '<div class="pm-row"><b>L\'entrée de commande du relais</b> → <code>GPIO26</code>. Le contact sec <code>O</code>/<code>I</code> des bornes va vers Ouvrir.</div>
           <div class="pm-row"><b>Alimentation</b> : AC 110–240 V ou DC 24–240 V sur les bornes.</div>
           <div class="pm-row"><b>Téléversement du programme</b> : pas d\'USB externe. Ouvrez le boîtier et raccordez un adaptateur USB-UART aux pastilles UART de l\'ESP32 (<code>3V3, GND, TX, RX</code> ; <code>IO0</code> à la masse pour entrer dans le bootloader). Le boîtier doit être <b>hors tension secteur</b>.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO16</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB or to the <code>5V</code>/<code>VIN</code> pin. The relay module takes its own <code>VCC</code>.</div>
           <div class="pm-row"><b>Uploading the program</b>: the board has USB and a converter on it — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>L\'entrée de commande du relais</b> → broche <code>GPIO16</code> (modifiable dans le formulaire ci-dessous).</div>
           <div class="pm-row"><b>Alimentation</b> : 5 V par USB ou sur la broche <code>5V</code>/<code>VIN</code>. Le module relais prend son propre <code>VCC</code>.</div>
           <div class="pm-row"><b>Téléversement du programme</b> : la carte dispose de l\'USB et d\'un convertisseur — le programme se téléverse <b>directement depuis le navigateur</b>, pas besoin de programmateur.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO16</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V to <code>5V</code> or 3.3 V to <code>3V3</code>, soldered. The relay module takes its own <code>VCC</code>.</div>
           <div class="pm-row"><b>Uploading the program</b>: a bare module has no USB — drop it into a programmer and upload through the programmer\'s micro-USB. Only power and the relay are soldered to the module itself (do not forget the common ground, GND).</div>' => '<div class="pm-row"><b>L\'entrée de commande du relais</b> → broche <code>GPIO16</code> (modifiable dans le formulaire ci-dessous).</div>
           <div class="pm-row"><b>Alimentation</b> : 5 V sur <code>5V</code> ou 3,3 V sur <code>3V3</code>, en soudure. Le module relais prend son propre <code>VCC</code>.</div>
           <div class="pm-row"><b>Téléversement du programme</b> : un module nu n\'a pas d\'USB — insérez-le dans un programmateur et téléversez le programme par son micro-USB. Sur le module lui-même, on ne soude que l\'alimentation et le relais (n\'oubliez pas la masse commune, GND).</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO3</code> (you can change it in the form).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB-C or 3.3 V to the <code>3V3</code> pin.</div>
           <div class="pm-row"><b>Uploading the program</b>: the board has USB-C — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>L\'entrée de commande du relais</b> → broche <code>GPIO3</code> (modifiable dans le formulaire).</div>
           <div class="pm-row"><b>Alimentation</b> : 5 V par USB-C ou 3,3 V sur la broche <code>3V3</code>.</div>
           <div class="pm-row"><b>Téléversement du programme</b> : la carte dispose de l\'USB-C — le programme se téléverse <b>directement depuis le navigateur</b>, pas besoin de programmateur.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO4</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V / 3.3 V, soldered to the module\'s pins.</div>
           <div class="pm-row"><b>Uploading the program</b>: a bare module goes into a programmer — you do not solder USB to it. Power and the relay are soldered.</div>' => '<div class="pm-row"><b>L\'entrée de commande du relais</b> → broche <code>GPIO4</code> (modifiable dans le formulaire ci-dessous).</div>
           <div class="pm-row"><b>Alimentation</b> : 5 V / 3,3 V, soudés aux broches du module.</div>
           <div class="pm-row"><b>Téléversement du programme</b> : un module nu passe par le programmateur, on ne lui soude pas d\'USB. L\'alimentation et le relais se soudent.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO4</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB or to the <code>5V</code>/<code>VIN</code> pin.</div>
           <div class="pm-row"><b>Uploading the program</b>: USB is on board — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>L\'entrée de commande du relais</b> → broche <code>GPIO4</code> (modifiable dans le formulaire ci-dessous).</div>
           <div class="pm-row"><b>Alimentation</b> : 5 V par USB ou sur la broche <code>5V</code>/<code>VIN</code>.</div>
           <div class="pm-row"><b>Téléversement du programme</b> : l\'USB est intégré — le programme se téléverse <b>directement depuis le navigateur</b>, pas besoin de programmateur.</div>',
    '<div class="pm-row"><b>The relay is already on the board</b>, controlled from <code>GPIO16</code>. Its <code>NO</code>+<code>COM</code> output goes to the drive\'s Open terminals.</div>
           <div class="pm-row"><b>Power</b>: 5 V over micro-USB, or 7–30 V to the power terminals.</div>
           <div class="pm-row"><b>Uploading the program</b>: micro-USB here is power only (there is no UART) — hook a USB-UART programmer to the <code>TX/RX/GND</code> pins and pull <code>IO0</code> to ground as you power it up.</div>' => '<div class="pm-row"><b>Le relais est déjà sur la carte</b>, commandé par <code>GPIO16</code>. La sortie <code>NO</code>+<code>COM</code> va aux bornes Open de la motorisation.</div>
           <div class="pm-row"><b>Alimentation</b> : 5 V par micro-USB ou 7–30 V sur les bornes d\'alimentation.</div>
           <div class="pm-row"><b>Téléversement du programme</b> : ici le micro-USB ne sert qu\'à l\'alimentation (pas d\'UART) — branchez un programmateur USB-UART sur les broches <code>TX/RX/GND</code> et mettez <code>IO0</code> à la masse à la mise sous tension.</div>',
    '<div class="pm-row">The pinout and flashing are the same as on the Plus 1: relay <code>GPIO26</code>, dry contact <code>O</code>/<code>I</code> to Open.</div>
           <div class="pm-row"><b>Power</b>: AC 110–240 V.</div>
           <div class="pm-row"><b>Uploading the program</b>: open the case, USB-UART to the ESP32\'s UART pads (<code>3V3/GND/TX/RX</code>, <code>IO0</code> to ground). The power-metering chip is unused by the Entrixy firmware. Disconnect it from the mains.</div>' => '<div class="pm-row">Le brochage et le flashage sont les mêmes que sur le Plus 1 : relais <code>GPIO26</code>, contact sec <code>O</code>/<code>I</code> vers Ouvrir.</div>
           <div class="pm-row"><b>Alimentation</b> : AC 110–240 V.</div>
           <div class="pm-row"><b>Téléversement du programme</b> : ouvrez le boîtier, USB-UART sur les pastilles UART de l\'ESP32 (<code>3V3/GND/TX/RX</code>, <code>IO0</code> à la masse). Le micrologiciel Entrixy n\'utilise pas la puce de mesure. Mettez hors tension secteur.</div>',
    'account' => 'mon compte',
    'Two bytes of tag are deliberate: the state byte only drives the open/closed indicator
and grants no authority, while every extra byte of advertisement costs battery on every
wake-up. The tag guards against corruption on the air, not against a forger — 16 bits
fall to brute force in seconds. Nothing that decides access may travel this way.' => 'Deux octets d’étiquette, c’est délibéré : l’octet d’état ne pilote que l’indicateur ouvert/fermé et n’accorde aucun droit, tandis que chaque octet supplémentaire de l’annonce coûte de la batterie à chaque réveil. L’étiquette protège d’une altération dans les ondes, pas d’un faussaire — 16 bits tombent en quelques secondes. Rien de ce qui décide de l’accès ne doit passer par là.',
    'Domain' => 'Domaine',
    'expired' => 'expiré',
    'This link has already been used: access for this visit is granted. If it was you, the company is in your app under companies, together with the log of openings — you take the access back there at any time. If the link reached you by chance, ask the company for a new one: each link works once.' => 'Ce lien a déjà servi : l’accès pour cette visite est accordé. Si c’était vous, l’entreprise figure dans votre application sous « entreprises », avec le journal des ouvertures — vous y reprenez l’accès quand vous voulez. Si le lien vous est parvenu par hasard, demandez-en un nouveau à l’entreprise : chaque lien ne sert qu’une fois.',
    'Copy the link' => 'Copier le lien',
    'Be sure to check the domain %s against the site of the company you are about to grant access to.' => 'Vérifiez impérativement le domaine %s avec le site de l’entreprise à qui vous allez accorder l’accès.',
    'This company has not confirmed a domain — there is only the name it entered. Grant access if you are sure who is asking.' => 'Cette entreprise n’a pas confirmé de domaine — il n’y a que le nom indiqué. Accordez l’accès si vous savez qui demande.',
    'The link is copied: after installation the app will pick it up itself, scanning again is not needed.' => 'Le lien est copié : après l’installation, l’application le reprendra d’elle-même, inutile de scanner à nouveau.',
    'Powered by Entrixy' => 'Propulsé par Entrixy',
];
