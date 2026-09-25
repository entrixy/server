<?php
/* Перевод сайта: [английская строка => перевод]. Основной язык — английский. */
return [
    'Guide' => 'Руководство',
    'App' => 'Приложение',
    'Install the app' => 'Установить приложение',
    'Accept' => 'Принять',
    'Time' => 'Время',
    'Security' => 'Безопасность',
    '. The' => '. Чип',
    'Open' => 'Откройте',
    'and' => 'и',
    'QR code' => 'QR-код',
    'Link' => 'Ссылка',
    'Text' => 'Текст',
    'OR' => 'ИЛИ',
    'AND' => 'И',
    'The' => 'В каталоге',
    'Copy' => 'Скопировать',
    'Access request — Entrixy' => 'Запрос доступа — Entrixy',
    'A service is asking for access to your barrier. Decide yourself what to grant and take it back at any time.' => 'Сервис просит доступ к вашему шлагбауму. Вы сами решаете, что дать, и в любой момент забираете обратно.',
    'Access to your barrier' => 'Доступ к вашему шлагбауму',
    'You decide what to grant, see every opening in the log and take access back in one tap.' => 'Вы решаете, что дать, видите каждое открытие в журнале и забираете доступ одним нажатием.',
    'This company is asking for access to your barrier so that its employee can drive in on the day of the visit. Access is granted to the company, not to a particular person, and every opening is recorded in your log with the name of whoever pressed the button.' => 'Эта компания просит доступ к вашему шлагбауму, чтобы её сотрудник смог заехать в день визита. Доступ выдаётся компании, а не конкретному человеку, и каждое открытие попадает в ваш журнал с именем того, кто нажал.',
    'Install the app and add your barrier — it takes a couple of minutes.' => 'Поставьте приложение и добавьте свой шлагбаум — это пара минут.',
    'Grant access: the company will already be waiting in the list, nothing to copy or forward.' => 'Выдайте доступ: компания уже будет ждать в списке, ничего копировать и пересылать не нужно.',
    'Take it back whenever you want. The company cannot pass the access on to anyone else.' => 'Заберите обратно когда захотите. Передать этот доступ дальше компания не может.',
    'Your barrier has to open on a call from your number, and your phone has to stay online — the app dials for you at the moment of the request. If your barrier has an Entrixy controller, the phone is not needed at all.' => 'Ваш шлагбаум должен открываться звонком с вашего номера, а телефон — оставаться в сети: в момент запроса приложение звонит за вас. Если на шлагбауме стоит контроллер Entrixy, телефон не нужен вовсе.',
    'This request has expired. Ask the company for a new link — it takes them one click.' => 'Срок этого запроса истёк. Попросите у компании новую ссылку — это одно нажатие с их стороны.',
    'This link is not valid. Check that the address was scanned in full, or ask the company for a new one.' => 'Эта ссылка недействительна. Проверьте, что адрес считался целиком, или попросите у компании новую.',
    'State' => 'Состояние',
    'Logo' => 'Логотип',
    'domain not confirmed' => 'домен не подтверждён',
    'Android app' => 'Приложение для Android',
    'guide' => 'руководство',
    '.
        Do you manufacture hardware?' => '.
        Производите оборудование?',
    'app' => 'приложение',
    'server' => 'сервер',
    'to your' => 'на ваш',
    'Compute' => 'Посчитайте',
    'POST &lt;your webhook_url&gt;
Content-Type: application/json

{
  "action":    "open",
  "object_id": 42,
  "timestamp": 1750000000,
  "nonce":     "0011223344556677",
  "signature": "9d7b58066094fa88..."
}' => 'POST &lt;ваш webhook_url&gt;
Content-Type: application/json

{
  "action":    "open",
  "object_id": 42,
  "timestamp": 1750000000,
  "nonce":     "0011223344556677",
  "signature": "9d7b58066094fa88..."
}',
    'objects' => 'объектов',
    'Open in the app' => 'Открыть в приложении',
    'with its own' => 'своим',
    'Code' => 'Код',
    'offset  size  field
[0..1]   2    Company ID = E0 00
[2..5]   4    device_id            (LE)
[6..9]   4    counter              (LE, monotonic, anti-replay, survives deep sleep)
[10..17] 8    auth_hmac            = HMAC(owner_secret, mac_in)[0..7]
[18]     1    sleep_interval_s     (plaintext)
[19..22] 4    opts_cipher          (battery, status, fw, hw — encrypted)' => 'offset  size  поле
[0..1]   2    Company ID = E0 00
[2..5]   4    device_id            (LE)
[6..9]   4    counter              (LE, монотонный, anti-replay, переживает deep-sleep)
[10..17] 8    auth_hmac            = HMAC(owner_secret, mac_in)[0..7]
[18]     1    sleep_interval_s     (plaintext)
[19..22] 4    opts_cipher          (battery, status, fw, hw — зашифрованы)',
    'K_state = HKDF-SHA256(salt=null, ikm=owner_secret, info="ble-state-v1", L=16)
[..21] state_enc = state_byte XOR K_state[counter &amp; 15]     // bit0: 1=open, 0=closed
[22..23] state_mac = HMAC-SHA256(K_state, counter(4B LE) || state_enc)[0..1]   // 2 bytes' => 'K_state = HKDF-SHA256(salt=null, ikm=owner_secret, info="ble-state-v1", L=16)
[..21] state_enc = state_byte XOR K_state[counter &amp; 15]     // бит0: 1=открыто,0=закрыто
[22..23] state_mac = HMAC-SHA256(K_state, counter(4B LE) || state_enc)[0..1]   // 2 байта',
    'The server' => 'Сервер',
    'without' => 'без',
    'with' => 'с',
    'every' => 'каждые',
    'With' => 'При',
    'instead of' => 'вместо',
    'Check' => 'Проверка',
    'empty' => 'пустой',
    'Guest' => 'Гость',
    '→ device_hello
{ "type":"device_hello",
  "device_key":    "&lt;32 hex&gt;",
  "device_secret": "&lt;32 hex&gt;",
  "e2ee":          true|false }        // whether a valid ownerSecret exists (§5)' => '→ device_hello
{ "type":"device_hello",
  "device_key":    "&lt;32 hex&gt;",
  "device_secret": "&lt;32 hex&gt;",
  "e2ee":          true|false }        // есть ли валидный ownerSecret (§5)',
    '❮&nbsp; device_ok  { "type":"device_ok", "hb_interval":300 }   // success; hb_interval in s (10..3600)
← error      { "type":"error", "reason":"auth" }         // failure → the server closes' => '❮&nbsp; device_ok  { "type":"device_ok", "hb_interval":300 }   // успех; hb_interval сек (10..3600)
← error      { "type":"error", "reason":"auth" }         // провал → сервер закрывает',
    '❮&nbsp; device_command
{ "type":"device_command", "action":"open", "command_id":"&lt;id&gt;", "number_id":&lt;n&gt; }
  // action:"close" — for a bistable drive' => '❮&nbsp; device_command
{ "type":"device_command", "action":"open", "command_id":"&lt;id&gt;", "number_id":&lt;n&gt; }
  // action:"close" — для бистабильного привода',
    'PROVISION &lt;64 hex&gt;   → store the ownerSecret in NVS, return the fingerprint
WIPE                  → erase it (basic mode)
STATUS                → show the fingerprint
fingerprint = HMAC-SHA256(ownerSecret, "fp")[0..3]  (hex)' => 'PROVISION &lt;64 hex&gt;   → сохранить ownerSecret в NVS, вернуть fingerprint
WIPE                  → стереть (базовый режим)
STATUS                → показать fingerprint
fingerprint = HMAC-SHA256(ownerSecret, "fp")[0..3]  (hex)',
    'token (3B) = [guest_did 2B LE][perms 1B]                      // a capability, no TTL
owner_sig  = HMAC-SHA256(ownerSecret, token)[0..15]
guest_key  = HKDF-SHA256(salt=null, ikm=ownerSecret, info="guest"||guest_did(2B LE), L=32)
proof      = HMAC-SHA256(guest_key, nonce)[0..15]' => 'token (3B) = [guest_did 2B LE][perms 1B]                      // capability, без TTL
owner_sig  = HMAC-SHA256(ownerSecret, token)[0..15]
guest_key  = HKDF-SHA256(salt=null, ikm=ownerSecret, info="guest"||guest_did(2B LE), L=32)
proof      = HMAC-SHA256(guest_key, nonce)[0..15]',
    'OK' => 'ОК',
    'On' => 'Включён',
    'Off' => 'Выключен',
    'or' => 'или',
    'Bistable mode: the controller remembers the current position (open or closed) and
toggles it on every activation. The position is visible on the object icon in the app,
to owner and guest alike. The pin for the Close command is set below, in the Pins section.' => 'Бистабильный режим: контроллер запоминает текущее положение (открыто или закрыто) и
переключает его при каждом срабатывании. Положение видно в приложении на значке объекта —
и владельцу, и гостю. Вывод для команды "Закрыть" задаётся ниже, в секции "Пины".',
    'Language' => 'Язык',
    'Config' => 'Конфиг',
    'or the' => 'или',
    'Name' => 'Название',
    'Type' => 'Тип',
    'Access' => 'Доступ',
    'Everyone' => 'Всем',
    'active' => 'активен',
    '<div class="pm-row"><b>A 30 A relay is on the board</b>, controlled from <code>GPIO16</code>. <code>NO</code>+<code>COM</code> go to the Open terminals.</div>
           <div class="pm-row"><b>Power</b>: straight from the <b>mains</b> to the AC terminals — the power supply is built into the board.</div>
           <div class="pm-row"><b>Uploading the program</b>: a USB-UART programmer on the <code>TX/RX/GND</code> pins. <b>Flash the board DISCONNECTED from the mains</b> — powered from the programmer only.</div>' => '<div class="pm-row"><b>Реле 30 А на плате</b>, управление — <code>GPIO16</code>. <code>NO</code>+<code>COM</code> на клеммы "Открыть".</div>
           <div class="pm-row"><b>Питание</b>: прямо в <b>сеть</b> на клеммы AC — блок питания распаян на плате.</div>
           <div class="pm-row"><b>Загрузка программы</b>: программатор USB-UART на пины <code>TX/RX/GND</code>. <b>Прошивайте плату ОТКЛЮЧЁННОЙ от сети</b> — питание только от программатора.</div>',
    '<div class="pm-row"><b>The relay control input</b> → <code>GPIO26</code>. The dry contact <code>O</code>/<code>I</code> on the terminals goes to Open.</div>
           <div class="pm-row"><b>Power</b>: AC 110–240 V or DC 24–240 V to the terminals.</div>
           <div class="pm-row"><b>Uploading the program</b>: there is no external USB. Open the case and connect a USB-UART adapter to the ESP32\'s UART pads (<code>3V3, GND, TX, RX</code>; <code>IO0</code> to ground to enter the bootloader). The case must be <b>disconnected from the mains</b>.</div>' => '<div class="pm-row"><b>Управляющий контакт реле</b> → <code>GPIO26</code>. Сухой контакт <code>O</code>/<code>I</code> на клеммах — на "Открыть".</div>
           <div class="pm-row"><b>Питание</b>: AC 110–240 В или DC 24–240 В на клеммы.</div>
           <div class="pm-row"><b>Загрузка программы</b>: внешнего USB нет. Вскройте корпус и подключитесь USB-UART адаптером к UART-пятакам ESP32 (<code>3V3, GND, TX, RX</code>; <code>IO0</code> на землю для входа в загрузчик). Корпус должен быть <b>обесточен от сети</b>.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO16</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB or to the <code>5V</code>/<code>VIN</code> pin. The relay module takes its own <code>VCC</code>.</div>
           <div class="pm-row"><b>Uploading the program</b>: the board has USB and a converter on it — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>Управляющий контакт реле</b> → пин <code>GPIO16</code> (можно сменить в форме ниже).</div>
           <div class="pm-row"><b>Питание</b>: 5 В по USB или на пин <code>5V</code>/<code>VIN</code>. Релейный модуль — своим <code>VCC</code>.</div>
           <div class="pm-row"><b>Загрузка программы</b>: на плате есть USB и преобразователь — программа загружается <b>прямо из браузера</b>, программатор не нужен.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO16</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V to <code>5V</code> or 3.3 V to <code>3V3</code>, soldered. The relay module takes its own <code>VCC</code>.</div>
           <div class="pm-row"><b>Uploading the program</b>: a bare module has no USB — drop it into a programmer and upload through the programmer\'s micro-USB. Only power and the relay are soldered to the module itself (do not forget the common ground, GND).</div>' => '<div class="pm-row"><b>Управляющий контакт реле</b> → пин <code>GPIO16</code> (можно сменить в форме ниже).</div>
           <div class="pm-row"><b>Питание</b>: 5 В на <code>5V</code> или 3.3 В на <code>3V3</code> — пайкой. Релейный модуль — своим <code>VCC</code>.</div>
           <div class="pm-row"><b>Загрузка программы</b>: у модуля без обвязки нет USB — вставьте его в программатор и загрузите программу через его micro-USB. К самому модулю припаиваются только питание и реле (не забудьте общий минус — "землю", GND).</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO3</code> (you can change it in the form).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB-C or 3.3 V to the <code>3V3</code> pin.</div>
           <div class="pm-row"><b>Uploading the program</b>: the board has USB-C — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>Управляющий контакт реле</b> → пин <code>GPIO3</code> (можно сменить в форме).</div>
           <div class="pm-row"><b>Питание</b>: 5 В по USB-C или 3.3 В на пин <code>3V3</code>.</div>
           <div class="pm-row"><b>Загрузка программы</b>: на плате есть USB-C — программа загружается <b>прямо из браузера</b>, программатор не нужен.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO4</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V / 3.3 V, soldered to the module\'s pins.</div>
           <div class="pm-row"><b>Uploading the program</b>: a bare module goes into a programmer — you do not solder USB to it. Power and the relay are soldered.</div>' => '<div class="pm-row"><b>Управляющий контакт реле</b> → пин <code>GPIO4</code> (можно сменить в форме ниже).</div>
           <div class="pm-row"><b>Питание</b>: 5 В / 3.3 В — пайкой к пинам модуля.</div>
           <div class="pm-row"><b>Загрузка программы</b>: модуль без обвязки — в программатор, USB к нему не паяют. Питание и реле — пайкой.</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO4</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB or to the <code>5V</code>/<code>VIN</code> pin.</div>
           <div class="pm-row"><b>Uploading the program</b>: USB is on board — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>Управляющий контакт реле</b> → пин <code>GPIO4</code> (можно сменить в форме ниже).</div>
           <div class="pm-row"><b>Питание</b>: 5 В по USB или на пин <code>5V</code>/<code>VIN</code>.</div>
           <div class="pm-row"><b>Загрузка программы</b>: USB на борту — программа загружается <b>прямо из браузера</b>, программатор не нужен.</div>',
    '<div class="pm-row"><b>The relay is already on the board</b>, controlled from <code>GPIO16</code>. Its <code>NO</code>+<code>COM</code> output goes to the drive\'s Open terminals.</div>
           <div class="pm-row"><b>Power</b>: 5 V over micro-USB, or 7–30 V to the power terminals.</div>
           <div class="pm-row"><b>Uploading the program</b>: micro-USB here is power only (there is no UART) — hook a USB-UART programmer to the <code>TX/RX/GND</code> pins and pull <code>IO0</code> to ground as you power it up.</div>' => '<div class="pm-row"><b>Реле уже на плате</b>, управление — <code>GPIO16</code>. Выход <code>NO</code>+<code>COM</code> идёт на клеммы "Открыть" привода.</div>
           <div class="pm-row"><b>Питание</b>: 5 В по micro-USB или 7–30 В на клеммы питания.</div>
           <div class="pm-row"><b>Загрузка программы</b>: micro-USB здесь только для питания (UART нет) — подключите программатор USB-UART к пинам <code>TX/RX/GND</code>, <code>IO0</code> на землю в момент включения.</div>',
    '<div class="pm-row">The pinout and flashing are the same as on the Plus 1: relay <code>GPIO26</code>, dry contact <code>O</code>/<code>I</code> to Open.</div>
           <div class="pm-row"><b>Power</b>: AC 110–240 V.</div>
           <div class="pm-row"><b>Uploading the program</b>: open the case, USB-UART to the ESP32\'s UART pads (<code>3V3/GND/TX/RX</code>, <code>IO0</code> to ground). The power-metering chip is unused by the Entrixy firmware. Disconnect it from the mains.</div>' => '<div class="pm-row">Распиновка и прошивка — как у Plus 1: реле <code>GPIO26</code>, сухой контакт <code>O</code>/<code>I</code> на "Открыть".</div>
           <div class="pm-row"><b>Питание</b>: AC 110–240 В.</div>
           <div class="pm-row"><b>Загрузка программы</b>: вскрыть корпус, USB-UART на UART-пятаки ESP32 (<code>3V3/GND/TX/RX</code>, <code>IO0</code> на землю). Чип замера мощности прошивкой Entrixy не используется. Обесточить от сети.</div>',
    'account' => 'кабинет',
    'Two bytes of tag are deliberate: the state byte only drives the open/closed indicator
and grants no authority, while every extra byte of advertisement costs battery on every
wake-up. The tag guards against corruption on the air, not against a forger — 16 bits
fall to brute force in seconds. Nothing that decides access may travel this way.' => 'Два байта тега — намеренно: байт состояния управляет только индикатором открыто/закрыто и никаких прав не даёт, а каждый лишний байт объявления стоит батареи на каждом пробуждении. Тег защищает от искажения в эфире, а не от подделывателя — 16 бит перебираются за секунды. Ничто, решающее доступ, этим путём ходить не должно.',
    'Domain' => 'Домен',
    'expired' => 'просрочено',
    'This link has already been used: access for this visit is granted. If it was you, the company is in your app under companies, together with the log of openings — you take the access back there at any time. If the link reached you by chance, ask the company for a new one: each link works once.' => 'Эта ссылка уже использована: доступ для этого визита выдан. Если это были вы — компания есть в приложении на вкладке компаний вместе с журналом открытий, там же доступ в любой момент забирается. Если ссылка попала к вам случайно, попросите у компании новую: каждая работает один раз.',
    'Copy the link' => 'Скопировать ссылку',
    'Be sure to check the domain %s against the site of the company you are about to grant access to.' => 'Обязательно сверьте домен %s с сайтом компании, которой собираетесь предоставить доступ.',
    'This company has not confirmed a domain — there is only the name it entered. Grant access if you are sure who is asking.' => 'Эта компания не подтвердила домен — есть только указанное название. Выдавайте доступ, если уверены, кто просит.',
    'The link is copied: after installation the app will pick it up itself, scanning again is not needed.' => 'Ссылка скопирована: после установки приложение подхватит её само, сканировать заново не нужно.',
    'Entrixy — open barriers, gates, locks and intercoms' => 'Entrixy — открывайте шлагбаумы, ворота, замки и домофоны',
    'Access control from your phone: open barriers, gates, locks and intercoms automatically.' => 'Управление доступом с телефона: открывайте шлагбаумы, ворота, замки и домофоны автоматически.',
    'Powered by Entrixy' => 'Работает на Entrixy',
];
