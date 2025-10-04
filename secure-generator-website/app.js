// Secure Password & Passphrase Generator
// Uses Web Crypto for randomness. No data leaves the browser.

const StorageKeys = {
  theme: 'pwgen_theme',
  passwordPrefs: 'pwgen_password_prefs',
  passphrasePrefs: 'pwgen_passphrase_prefs',
  passwordHistory: 'pwgen_password_history',
  passphraseHistory: 'pwgen_passphrase_history',
};

function readJsonFromLocalStorage(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function writeJsonToLocalStorage(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // ignore
  }
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function secureRandomIntExclusive(maxExclusive) {
  if (!Number.isFinite(maxExclusive) || maxExclusive <= 0) {
    throw new Error('Invalid maxExclusive for secureRandomIntExclusive');
  }
  const maxUint32 = 0xffffffff;
  const threshold = Math.floor((maxUint32 + 1) / maxExclusive) * maxExclusive;
  const arr = new Uint32Array(1);
  let x;
  do {
    crypto.getRandomValues(arr);
    x = arr[0];
  } while (x >= threshold);
  return x % maxExclusive;
}

function pickRandomCharFromSet(charset) {
  if (!charset || charset.length === 0) throw new Error('Empty charset');
  const idx = secureRandomIntExclusive(charset.length);
  return charset[idx];
}

const BASE_CHARSETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: "!@#$%^&*()-_=+[]{};:'\",.<>/?`~|\\",
};
const SIMILAR = new Set('ilLI|oO0'.split(''));
const AMBIGUOUS = new Set("{}[]()/\\'\"`~,;:.<>".split(''));

function buildCharset(options) {
  const groups = [];
  if (options.includeLower) groups.push('lower');
  if (options.includeUpper) groups.push('upper');
  if (options.includeDigits) groups.push('digits');
  if (options.includeSymbols) groups.push('symbols');

  let symbolSet = BASE_CHARSETS.symbols;
  if (options.customSymbols && options.customSymbols.trim().length > 0) {
    symbolSet = Array.from(new Set(options.customSymbols.split(''))).join('');
  }

  const groupToChars = {
    lower: BASE_CHARSETS.lower,
    upper: BASE_CHARSETS.upper,
    digits: BASE_CHARSETS.digits,
    symbols: symbolSet,
  };

  let poolSet = new Set();
  const groupPools = {};

  for (const g of groups) {
    let chars = groupToChars[g];
    if (options.excludeSimilar) {
      chars = chars.split('').filter((c) => !SIMILAR.has(c)).join('');
    }
    if (options.excludeAmbiguous && g === 'symbols') {
      chars = chars.split('').filter((c) => !AMBIGUOUS.has(c)).join('');
    }
    groupPools[g] = chars;
    for (const c of chars) poolSet.add(c);
  }

  const pool = Array.from(poolSet).join('');
  return { pool, groupPools, groups };
}

function shuffleInPlace(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = secureRandomIntExclusive(i + 1);
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

function generatePassword(options) {
  const { pool, groupPools, groups } = buildCharset(options);
  if (!pool || pool.length === 0) throw new Error('No characters selected');
  const length = clamp(options.length, 4, 128);

  const result = [];

  // Ensure at least one from each selected group
  if (options.requireEachSelectedGroup !== false) {
    for (const g of groups) {
      const gp = groupPools[g];
      if (gp && gp.length > 0) result.push(pickRandomCharFromSet(gp));
    }
  }

  while (result.length < length) {
    const nextChar = pickRandomCharFromSet(pool);
    if (options.noAdjacentDuplicates && result.length > 0 && result[result.length - 1] === nextChar) {
      // Try a different char; if pool size is 1, break to avoid infinite loop
      if (pool.length === 1) break;
      continue;
    }
    result.push(nextChar);
  }

  // If we overshot length due to required groups, trim
  if (result.length > length) result.length = length;

  // Shuffle to avoid predictable group placement
  shuffleInPlace(result);

  const raw = result.join('');
  return raw;
}

function groupPasswordDisplay(password, groupSize = 4, separator = '-') {
  if (!password) return '';
  const parts = [];
  for (let i = 0; i < password.length; i += groupSize) {
    parts.push(password.slice(i, i + groupSize));
  }
  return parts.join(separator);
}

function calculatePasswordEntropyBits(options) {
  const { pool } = buildCharset(options);
  if (!pool || pool.length === 0) return 0;
  const L = clamp(options.length, 0, 1024);
  const N = pool.length;
  if (L === 0) return 0;
  let bits;
  if (options.noAdjacentDuplicates && N > 1) {
    // Approximate: first char N choices, others (N-1)
    bits = Math.log2(N) + (L - 1) * Math.log2(N - 1);
  } else {
    bits = L * Math.log2(N);
  }
  return Math.max(0, bits);
}

function strengthFromBits(bits) {
  // Map bits to a 0-100 scale and label
  let label = 'Very Weak';
  if (bits >= 28 && bits < 36) label = 'Weak';
  else if (bits >= 36 && bits < 60) label = 'Reasonable';
  else if (bits >= 60 && bits < 80) label = 'Strong';
  else if (bits >= 80 && bits < 128) label = 'Very Strong';
  else if (bits >= 128) label = 'Excellent';

  const percent = clamp(Math.round((bits / 128) * 100), 0, 100);
  return { label, percent };
}

// Passphrase
const WORDS = [
  // A compact, curated list (~512 common words) for memorability; unique & lowercase
  'able','about','above','access','acid','across','act','active','actor','actual','add','admit','adult','advice','aero','after','again','agent','agree','ahead','aim','air','alarm','album','alert','alike','alive','allow','alpha','also','alter','always','amber','among','amount','amuse','angel','anger','angle','angry','animal','answer','apart','apple','apply','april','arch','argue','arise','armed','armor','around','arrive','arrow','art','artist','ascent','ask','asleep','asset','assist','atom','attack','august','aunt','author','auto','autumn','award','away','axis',
  'baby','back','badge','bag','bake','balance','ball','band','bank','bar','bare','bark','barn','base','basic','basket','bath','battle','beach','beam','bean','bear','beard','beast','beat','beauty','because','become','beef','before','begin','behave','behind','being','believe','bell','belly','belong','below','belt','bench','bend','berry','beside','best','bet','beyond','bicycle','bid','bike','bill','bird','birth','bison','bitter','black','blade','blame','blank','blast','bleed','blend','bless','blind','block','blood','bloom','blow','blue','board','boat','body','boil','bolt','bomb','bone','bonus','book','boost','boot','border','born','borrow','boss','both','bother','bottle','bottom','bounce','bow','bowl','box','boy','brain','brake','branch','brand','brass','brave','bread','break','brick','bridge','brief','bright','bring','brisk','broad','broke','brown','brush','bubble','buddy','budget','build','bulb','bulk','bullet','bundle','bunny','burger','buried','burn','burst','bus','bush','busy','butter','button','buyer',
  'cabin','cable','cactus','cage','cake','calm','camera','camp','canal','cancel','candy','canoe','canvas','canyon','cap','capital','captain','car','carbon','card','care','cargo','carpet','carry','cart','case','cash','castle','casual','cat','catch','cause','cave','ceiling','cell','cement','census','center','chain','chair','chalk','chance','change','chaos','charge','chart','chase','chat','cheap','check','cheek','cheer','cheese','chef','cherry','chess','chest','chief','child','chimney','choice','choose','chop','chorus','circle','city','civil','claim','clap','clarify','claw','clay','clean','clear','clerk','clever','client','cliff','climb','clinic','clock','close','cloth','cloud','clown','club','clue','coach','coal','coast','coat','coconut','code','coffee','coil','coin','cold','collar','collect','color','column','combat','combine','come','comet','comfort','comic','common','compass','copy','coral','core','corner','cost','cotton','couch','could','count','couple','course','cousin','cover','cow','coyote','crack','craft','crane','crash','crater','crawl','crazy','cream','create','credit','creek','crew','cricket','crime','crisp','critic','crop','cross','crowd','crown','crude','cruise','crush','cry','crystal','cube','culture','cup','custom','cute','cycle',
  'daily','damage','dance','danger','daring','dark','dash','data','date','daughter','dawn','day','deal','debate','debris','debt','debug','decade','decide','deck','decorate','decrease','deer','defense','define','delay','deliver','demand','denial','dent','depend','depth','desert','design','desk','detail','detect','develop','device','devote','dial','diamond','diary','dice','diesel','diet','differ','digital','dinner','dinosaur','direct','dirt','disco','dish','disk','dismiss','display','distance','diver','dizzy','doctor','dog','doll','dolphin','domain','donate','donkey','donor','door','dose','double','dove','draft','dragon','drama','drastic','draw','dream','dress','drift','drill','drink','drive','drop','drum','dry','duck','dune','during','dust','duty','dwarf','dynamic',
  'eager','eagle','early','earth','easel','east','easy','echo','edge','edit','educate','effect','effort','egg','eight','either','elbow','elder','elect','elegant','element','elephant','elite','embark','embody','embrace','emerge','emotion','employ','empower','empty','enable','enact','end','endless','endorse','enemy','energy','enforce','engage','engine','enhance','enjoy','enlist','enrich','enroll','ensure','enter','entire','entry','envelope','episode','equal','equip','era','erase','erode','error','escape','essay','essence','estate','ethics','event','every','evoke','exact','example','excess','exchange','excite','excuse','exercise','exhibit','exit','exotic','expand','expect','expire','explain','explore','export','expose','extend','extra','eye',
  'fabric','face','fact','factor','fade','fail','fair','faith','fall','false','fame','family','famous','fancy','fan','far','farm','fashion','fast','fat','fatal','father','fault','favorite','feature','federal','feed','feel','fence','fever','few','fiber','fiction','field','figure','file','film','filter','final','find','fine','finger','finish','fire','firm','first','fiscal','fish','fit','fix','flag','flame','flash','flat','flavor','flee','flight','flip','float','flock','floor','flower','fluid','flush','fly','foam','focus','fog','foil','fold','follow','food','fool','foot','force','forest','forget','fork','fortune','forum','forward','fossil','foster','found','fox','fragile','frame','free','fresh','friend','fringe','frog','front','frozen','fruit','fuel','fun','funny','furnace','fury','future',
  'gain','galaxy','gallery','game','gap','garage','garlic','gas','gasp','gate','gather','gauge','gear','gecko','geek','gem','general','genius','genre','gentle','genuine','ghost','giant','gift','giggle','ginger','giraffe','girl','give','glad','glance','glare','glass','glide','globe','gloom','glory','glove','glow','glue','goal','goat','gold','golf','good','goose','gorilla','gossip','govern','gown','grab','grace','grade','grain','grant','grape','graph','grasp','grass','grave','gravity','gray','great','green','grid','grief','grill','grin','grip','ground','group','grow','grunt','guard','guess','guide','guilt','guitar','gulf','gummy',
  'habit','hair','half','hammer','hand','handle','happy','harbor','hard','harsh','harvest','hat','have','hawk','hazard','head','health','heart','heavy','hedge','height','hello','helmet','help','hen','hero','hidden','high','hill','hint','hip','hire','history','hobby','hockey','hold','holiday','hollow','home','honey','hood','hope','horn','horse','hospital','host','hotel','hour','house','hover','hub','huge','human','humble','humor','hundred','hungry','hunt','hurry','hurt','husband',
  'ice','icon','idea','identify','idle','ignore','ill','image','imitate','immune','impact','impose','improve','impulse','inch','include','income','increase','index','industry','infant','inflict','inform','inherit','injury','inner','input','inquire','inside','inspire','install','intact','interest','into','invest','invite','involve','iron','island','isolate','issue','item',
  'jacket','jaguar','jazz','jeans','jeep','jelly','jewel','job','join','joke','journey','joy','judge','juice','jump','jungle','junior','jury',
  'kangaroo','keen','keep','kettle','key','kick','kid','kidney','kind','king','kiss','kit','kitchen','kite','kitten','kiwi',
  'label','labor','lace','ladder','lady','lake','lamp','language','large','laser','last','late','laugh','laundry','lava','law','lawn','layer','lazy','leader','leaf','learn','leave','lecture','left','leg','legal','lemon','lend','length','lens','leopard','lesson','letter','level','liar','liberty','library','license','life','lift','light','like','limb','limit','line','lion','liquid','list','little','live','lizard','load','loan','local','locker','logic','logo','lonely','long','loop','loose','lord','lose','loss','lost','lottery','loud','love','loyal','lucky','lumber','lunar','lunch','luxury',
  'machine','mad','magic','magnet','mail','main','major','make','mammal','man','manage','mandate','mango','mansion','manual','maple','marble','march','margin','marine','market','marry','mask','mass','master','match','material','math','matter','maximum','maze','meadow','mean','measure','meat','mechanic','medal','media','melody','melt','member','memory','mention','menu','merit','merry','mesh','message','metal','method','middle','might','mild','milk','million','mint','minute','miracle','mirror','misery','mix','mobile','model','modify','moment','monitor','monkey','month','mood','moon','moral','more','morning','mortgage','mother','motion','motor','mountain','mouse','move','movie','much','muffin','mule','museum','music','must','mystery',
  'narrow','nation','nature','near','neat','neck','need','negative','neglect','neon','nerve','nest','net','network','neutral','never','news','next','nice','night','noble','noise','nomad','north','nose','notable','note','nothing','notice','novel','nuclear','number','nurse','nut',
  'oak','obey','object','oblige','obscure','observe','obtain','ocean','october','odor','off','offer','office','often','oil','okay','old','olive','olympic','omit','once','one','onion','online','only','onto','open','opera','opinion','oppose','option','orange','orbit','order','ordinary','organ','orient','original','other','otter','outdoor','outer','output','outside','oval','oven','over','owl','own','oxygen',
  'pact','page','pair','palace','palm','panda','panel','panic','panther','paper','parade','parcel','parent','park','parrot','party','pass','past','patch','path','patient','pause','pave','payment','peace','peanut','pear','pearl','pedal','peel','peep','peer','pen','penalty','pencil','people','pepper','perfect','permit','person','pet','phase','phone','photo','piano','pick','picture','piece','pilot','pink','pipe','pistol','pitch','pizza','place','plain','plan','planet','plant','plastic','plate','play','please','pledge','plug','plural','plus','poem','poet','point','polar','police','polite','pond','pony','pool','popular','portion','position','possible','post','potato','pottery','pouch','pound','pour','power','practice','praise','press','pretty','price','pride','prime','print','prior','prison','private','prize','problem','process','profit','program','project','promise','proof','propel','prosper','protect','proud','prove','public','puffy','pull','pulp','pulse','pump','punch','pupil','puppy','purchase','purple','push','puzzle',
  'quality','quantum','quarter','queen','query','quick','quiet','quote',
  'rabbit','race','rack','radar','radio','rail','rain','raise','rally','ramp','ranch','random','range','rapid','rare','rate','rather','raven','raw','razor','reach','react','read','ready','real','reason','rebel','rebuild','recall','receive','record','recycle','reduce','refer','reflect','reform','refuse','region','regret','regular','reject','relax','release','relief','rely','remain','remark','remind','remove','render','renew','rent','repair','repeat','replace','reply','report','request','rescue','resist','resource','response','result','retire','retreat','return','reunion','reveal','review','reward','rhythm','ribbon','rice','rich','ride','ridge','rifle','right','rigid','ring','riot','ripple','rise','risk','ritual','rival','river','road','roast','robot','robust','rock','rocket','romance','roof','room','rotate','rough','round','route','royal','rubber','rude','rug','rule','run','rural','rush',
  'saddle','safe','sail','salad','salary','salmon','salt','same','sample','sand','satisfy','sauce','save','scale','scan','scare','scene','school','science','scissors','scout','scrap','screen','script','scroll','sea','search','season','seat','second','secret','section','secure','seed','seek','segment','select','self','sell','seminar','senior','sense','sensor','series','service','session','settle','seven','shadow','shaft','shallow','share','shed','shell','sheriff','shield','shift','shine','ship','shirt','shock','shoe','shoot','shop','short','shoulder','shout','show','shrink','shuffle','sibling','sick','side','sight','sign','silent','silk','silver','simple','since','sing','siren','sister','situate','six','size','skate','skill','skin','skirt','skull','slab','slam','slap','sleep','slope','slot','slow','small','smart','smile','smoke','smooth','snack','snake','snap','snow','soap','soccer','social','sock','soda','soft','solar','soldier','solid','solution','solve','someone','song','soon','sorry','sort','soul','sound','soup','source','south','space','spare','speak','special','speed','spell','spend','sphere','spice','spider','spike','spin','spirit','spoil','sponsor','spoon','sport','spot','spray','spread','spring','spy','square','squeeze','square','squirrel','stable','staff','stage','stair','stamp','stand','start','state','stay','steak','steel','stem','step','stick','still','sting','stock','stomach','stone','stop','store','storm','story','stove','strategy','street','strike','strong','student','studio','stuff','style','subject','submit','subway','success','sudden','suffer','sugar','suit','summer','sun','sunny','sunset','super','supply','support','sure','surface','surge','surprise','survey','sushi','suspect','sustain','swamp','swap','swarm','swear','sweat','sweep','sweet','swift','swing','switch','sword','symbol','sync',
  'table','tackle','tactic','tail','talent','talk','tank','tape','target','task','taste','tattoo','taxi','teach','team','tease','technician','teen','teeth','tell','temple','ten','tennis','tent','term','test','text','thank','that','theme','then','theory','there','they','thick','thief','thigh','thing','think','third','thrive','throw','thumb','thunder','ticket','tide','tiger','tilt','timber','time','tiny','tip','tired','tissue','title','toast','tobacco','today','toddler','toe','together','toilet','token','tomato','tomorrow','tonight','tool','tooth','top','topic','torch','tornado','tortoise','toss','total','tourist','toward','tower','town','toy','track','trade','traffic','train','transfer','trap','trash','travel','tray','treat','tree','trend','trial','tribe','trick','trigger','trim','trip','trophy','truck','true','truly','trumpet','trust','truth','tube','tuna','tunnel','turkey','turn','turtle','twelve','twenty','twice','twin','twist','two','type',
  'umbrella','unable','uncle','under','undo','unfair','unfold','unique','unit','universe','unknown','unlock','until','unusual','update','upgrade','upper','upset','urban','urge','usage','use','used','useful','user','usual',
  'vacant','vacuum','vague','valid','valley','value','van','vanish','vapor','various','vast','vault','vehicle','velvet','vendor','venue','version','very','vessel','veteran','viable','vibrant','victim','video','view','village','vintage','violin','virtual','virus','visa','visit','visual','vital','vivid','vocal','voice','volume','vote','voyage',
  'wage','wagon','wait','walk','wall','walnut','want','war','warm','warn','washer','wasp','waste','water','wave','way','wealth','weapon','wear','weasel','weather','web','wedding','week','weird','welcome','west','wet','whale','wheat','wheel','when','where','which','while','whisper','white','whole','why','wide','width','wife','wild','will','win','window','wine','wing','wink','winner','winter','wire','wisdom','wise','wish','witness','wolf','woman','wonder','wood','wool','word','work','world','worry','worth','wrap','wreck','write','wrong',
  'yard','year','yellow','yesterday','yet','yield','young','youth',
  'zebra','zero','zone','zoo'
];

function randomWord() {
  return WORDS[secureRandomIntExclusive(WORDS.length)];
}

function applyCapitalization(word, mode) {
  switch (mode) {
    case 'title':
      return word.charAt(0).toUpperCase() + word.slice(1);
    case 'upper':
      return word.toUpperCase();
    case 'random':
      return Math.random() < 0.5
        ? word.charAt(0).toUpperCase() + word.slice(1)
        : word;
    case 'lower':
    default:
      return word;
  }
}

function generatePassphrase(options) {
  const numWords = clamp(options.numWords, 3, 10);
  const words = [];
  for (let i = 0; i < numWords; i++) {
    const w = randomWord();
    words.push(applyCapitalization(w, options.capitalization));
  }
  let sep = options.separator ?? '-';
  if (typeof sep !== 'string' || sep.length === 0) sep = '-';
  let phrase = words.join(sep);
  if (options.addNumber) {
    const n1 = secureRandomIntExclusive(10);
    const n2 = secureRandomIntExclusive(10);
    phrase += String(n1) + String(n2);
  }
  if (options.addSymbol) {
    const symbols = (options.symbols || '!@#$%^&*').split('');
    phrase += symbols[secureRandomIntExclusive(symbols.length)];
  }
  return phrase;
}

function calculatePassphraseEntropyBits(options) {
  const numWords = clamp(options.numWords, 0, 64);
  const base = Math.log2(WORDS.length) * numWords;
  let extra = 0;
  if (options.addNumber) extra += Math.log2(100); // two digits
  if (options.addSymbol) extra += Math.log2((options.symbols || '!@#$%^&*').length);
  return base + extra;
}

// UI
const ui = {
  // Tabs
  tabPassword: document.getElementById('tab-password'),
  tabPassphrase: document.getElementById('tab-passphrase'),
  panelPassword: document.getElementById('panel-password'),
  panelPassphrase: document.getElementById('panel-passphrase'),

  // Theme
  themeToggle: document.getElementById('themeToggle'),

  // Password elements
  passwordOutput: document.getElementById('passwordOutput'),
  btnGeneratePassword: document.getElementById('btnGeneratePassword'),
  btnCopyPassword: document.getElementById('btnCopyPassword'),
  btnCopyPasswordFormatted: document.getElementById('btnCopyPasswordFormatted'),
  btnTogglePassword: document.getElementById('btnTogglePassword'),
  strengthMeter: document.getElementById('strengthMeter'),
  strengthLabel: document.getElementById('strengthLabel'),
  entropyLabel: document.getElementById('entropyLabel'),

  presetSelect: document.getElementById('presetSelect'),
  lengthRange: document.getElementById('lengthRange'),
  lengthNumber: document.getElementById('lengthNumber'),
  optLower: document.getElementById('optLower'),
  optUpper: document.getElementById('optUpper'),
  optDigits: document.getElementById('optDigits'),
  optSymbols: document.getElementById('optSymbols'),
  optExcludeSimilar: document.getElementById('optExcludeSimilar'),
  optExcludeAmbiguous: document.getElementById('optExcludeAmbiguous'),
  optNoAdjacent: document.getElementById('optNoAdjacent'),
  optGroup: document.getElementById('optGroup'),
  symbolsInput: document.getElementById('symbolsInput'),

  passwordHistoryList: document.getElementById('passwordHistory'),
  btnClearPasswordHistory: document.getElementById('btnClearPasswordHistory'),

  // Passphrase elements
  passphraseOutput: document.getElementById('passphraseOutput'),
  btnGeneratePassphrase: document.getElementById('btnGeneratePassphrase'),
  btnCopyPassphrase: document.getElementById('btnCopyPassphrase'),
  phraseStrengthMeter: document.getElementById('phraseStrengthMeter'),
  phraseStrengthLabel: document.getElementById('phraseStrengthLabel'),
  phraseEntropyLabel: document.getElementById('phraseEntropyLabel'),

  wordsRange: document.getElementById('wordsRange'),
  wordsNumber: document.getElementById('wordsNumber'),
  sepInput: document.getElementById('sepInput'),
  capSelect: document.getElementById('capSelect'),
  optAddNumber: document.getElementById('optAddNumber'),
  optAddSymbol: document.getElementById('optAddSymbol'),
  phraseSymbolsInput: document.getElementById('phraseSymbolsInput'),
  passphraseHistoryList: document.getElementById('passphraseHistory'),
  btnClearPassphraseHistory: document.getElementById('btnClearPassphraseHistory'),
};

function readPasswordOptions() {
  return {
    length: Number(ui.lengthNumber.value) || Number(ui.lengthRange.value) || 16,
    includeLower: ui.optLower.checked,
    includeUpper: ui.optUpper.checked,
    includeDigits: ui.optDigits.checked,
    includeSymbols: ui.optSymbols.checked,
    excludeSimilar: ui.optExcludeSimilar.checked,
    excludeAmbiguous: ui.optExcludeAmbiguous.checked,
    noAdjacentDuplicates: ui.optNoAdjacent.checked,
    customSymbols: ui.symbolsInput.value || undefined,
    requireEachSelectedGroup: true,
  };
}

function readPassphraseOptions() {
  return {
    numWords: Number(ui.wordsNumber.value) || Number(ui.wordsRange.value) || 4,
    separator: ui.sepInput.value,
    capitalization: ui.capSelect.value,
    addNumber: ui.optAddNumber.checked,
    addSymbol: ui.optAddSymbol.checked,
    symbols: ui.phraseSymbolsInput.value,
  };
}

function syncLengthInputs() {
  const v = clamp(Number(ui.lengthRange.value), 4, 128);
  ui.lengthRange.value = String(v);
  ui.lengthNumber.value = String(v);
}

function syncWordsInputs() {
  const v = clamp(Number(ui.wordsRange.value), 3, 10);
  ui.wordsRange.value = String(v);
  ui.wordsNumber.value = String(v);
}

function renderPassword(password, options) {
  const displayed = options.group ? groupPasswordDisplay(password) : password;
  ui.passwordOutput.value = displayed;
  ui.passwordOutput.dataset.raw = password;

  const bits = calculatePasswordEntropyBits({ ...options, group: undefined });
  const { label, percent } = strengthFromBits(bits);
  ui.strengthMeter.value = percent;
  ui.strengthLabel.textContent = `Strength: ${label}`;
  ui.entropyLabel.textContent = `Entropy: ${bits.toFixed(1)} bits`;
}

function renderPassphrase(phrase, options) {
  ui.passphraseOutput.value = phrase;
  const bits = calculatePassphraseEntropyBits(options);
  const { label, percent } = strengthFromBits(bits);
  ui.phraseStrengthMeter.value = percent;
  ui.phraseStrengthLabel.textContent = `Strength: ${label}`;
  ui.phraseEntropyLabel.textContent = `Entropy: ${bits.toFixed(1)} bits`;
}

function copyText(value) {
  if (!value) return;
  navigator.clipboard.writeText(value).catch(() => {
    // Fallback: select and copy
    const ta = document.createElement('textarea');
    ta.value = value;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  });
}

function addToHistory(kind, value, meta) {
  const key = kind === 'password' ? StorageKeys.passwordHistory : StorageKeys.passphraseHistory;
  const list = readJsonFromLocalStorage(key, []);
  list.unshift({ value, meta, ts: Date.now() });
  const limit = 20;
  if (list.length > limit) list.length = limit;
  writeJsonToLocalStorage(key, list);
}

function renderHistory(kind) {
  const key = kind === 'password' ? StorageKeys.passwordHistory : StorageKeys.passphraseHistory;
  const listElem = kind === 'password' ? ui.passwordHistoryList : ui.passphraseHistoryList;
  const list = readJsonFromLocalStorage(key, []);
  listElem.innerHTML = '';
  for (const item of list) {
    const li = document.createElement('li');
    li.className = 'history-item';
    const valueSpan = document.createElement('span');
    valueSpan.className = 'history-value';
    valueSpan.textContent = item.value;
    const right = document.createElement('div');
    right.style.display = 'flex';
    right.style.gap = '8px';

    const meta = document.createElement('span');
    meta.className = 'history-meta';
    const d = new Date(item.ts);
    meta.textContent = d.toLocaleString();

    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', () => copyText(item.value));

    right.appendChild(meta);
    right.appendChild(copyBtn);

    li.appendChild(valueSpan);
    li.appendChild(right);
    listElem.appendChild(li);
  }
}

function loadPrefsIntoUI() {
  const pp = readJsonFromLocalStorage(StorageKeys.passwordPrefs, null);
  if (pp) {
    ui.lengthRange.value = String(pp.length ?? 16);
    ui.lengthNumber.value = String(pp.length ?? 16);
    ui.optLower.checked = !!pp.includeLower;
    ui.optUpper.checked = !!pp.includeUpper;
    ui.optDigits.checked = !!pp.includeDigits;
    ui.optSymbols.checked = !!pp.includeSymbols;
    ui.optExcludeSimilar.checked = !!pp.excludeSimilar;
    ui.optExcludeAmbiguous.checked = !!pp.excludeAmbiguous;
    ui.optNoAdjacent.checked = !!pp.noAdjacentDuplicates;
    ui.optGroup.checked = !!pp.group;
    ui.symbolsInput.value = pp.customSymbols || '';
  }

  const ph = readJsonFromLocalStorage(StorageKeys.passphrasePrefs, null);
  if (ph) {
    ui.wordsRange.value = String(ph.numWords ?? 4);
    ui.wordsNumber.value = String(ph.numWords ?? 4);
    ui.sepInput.value = ph.separator ?? '-';
    ui.capSelect.value = ph.capitalization ?? 'lower';
    ui.optAddNumber.checked = !!ph.addNumber;
    ui.optAddSymbol.checked = !!ph.addSymbol;
    ui.phraseSymbolsInput.value = ph.symbols ?? '!@#$%^&*';
  }
}

function savePasswordPrefs(extra = {}) {
  const opts = readPasswordOptions();
  const prefs = { ...opts, group: ui.optGroup.checked, ...extra };
  writeJsonToLocalStorage(StorageKeys.passwordPrefs, prefs);
}

function savePassphrasePrefs() {
  const opts = readPassphraseOptions();
  writeJsonToLocalStorage(StorageKeys.passphrasePrefs, opts);
}

// Presets
const PRESETS = {
  balanced: () => ({ length: 12, includeLower: true, includeUpper: true, includeDigits: true, includeSymbols: true, excludeSimilar: false, excludeAmbiguous: false, noAdjacentDuplicates: true, customSymbols: '' }),
  strong: () => ({ length: 16, includeLower: true, includeUpper: true, includeDigits: true, includeSymbols: true, excludeSimilar: false, excludeAmbiguous: false, noAdjacentDuplicates: true, customSymbols: '' }),
  paranoid: () => ({ length: 24, includeLower: true, includeUpper: true, includeDigits: true, includeSymbols: true, excludeSimilar: true, excludeAmbiguous: true, noAdjacentDuplicates: true, customSymbols: '' }),
  pin6: () => ({ length: 6, includeLower: false, includeUpper: false, includeDigits: true, includeSymbols: false, excludeSimilar: false, excludeAmbiguous: false, noAdjacentDuplicates: false, customSymbols: '' }),
  memorable: () => ({ length: 16, includeLower: true, includeUpper: false, includeDigits: true, includeSymbols: false, excludeSimilar: true, excludeAmbiguous: false, noAdjacentDuplicates: true, customSymbols: '' }),
  tech32: () => ({ length: 32, includeLower: true, includeUpper: true, includeDigits: true, includeSymbols: false, excludeSimilar: true, excludeAmbiguous: false, noAdjacentDuplicates: true, customSymbols: '' }),
};

function applyPresetToUI(presetName) {
  const fn = PRESETS[presetName];
  if (!fn) return;
  const p = fn();
  ui.lengthRange.value = String(p.length);
  ui.lengthNumber.value = String(p.length);
  ui.optLower.checked = p.includeLower;
  ui.optUpper.checked = p.includeUpper;
  ui.optDigits.checked = p.includeDigits;
  ui.optSymbols.checked = p.includeSymbols;
  ui.optExcludeSimilar.checked = p.excludeSimilar;
  ui.optExcludeAmbiguous.checked = p.excludeAmbiguous;
  ui.optNoAdjacent.checked = p.noAdjacentDuplicates;
  ui.optGroup.checked = presetName === 'memorable';
  ui.symbolsInput.value = p.customSymbols || '';
  savePasswordPrefs({ preset: presetName });
}

function generateAndRenderPassword() {
  try {
    const opts = readPasswordOptions();
    const pwd = generatePassword(opts);
    const group = ui.optGroup.checked;
    renderPassword(pwd, { ...opts, group });
    addToHistory('password', group ? groupPasswordDisplay(pwd) : pwd, { length: opts.length });
    renderHistory('password');
    savePasswordPrefs();
  } catch (err) {
    ui.passwordOutput.value = String(err.message || err);
  }
}

function generateAndRenderPassphrase() {
  const opts = readPassphraseOptions();
  const phrase = generatePassphrase(opts);
  renderPassphrase(phrase, opts);
  addToHistory('passphrase', phrase, { words: opts.numWords });
  renderHistory('passphrase');
  savePassphrasePrefs();
}

function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
}

function initTheme() {
  const saved = localStorage.getItem(StorageKeys.theme);
  const html = document.documentElement;
  if (saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    html.setAttribute('data-theme', 'dark');
  } else {
    html.setAttribute('data-theme', 'light');
  }
}

function toggleTheme() {
  const html = document.documentElement;
  const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem(StorageKeys.theme, next);
}

function setupTabs() {
  function activate(name) {
    const isPassword = name === 'password';
    ui.tabPassword.classList.toggle('active', isPassword);
    ui.tabPassphrase.classList.toggle('active', !isPassword);
    ui.panelPassword.classList.toggle('active', isPassword);
    ui.panelPassphrase.classList.toggle('active', !isPassword);
    ui.panelPassphrase.hidden = isPassword;
    ui.panelPassword.hidden = !isPassword;
  }
  ui.tabPassword.addEventListener('click', () => activate('password'));
  ui.tabPassphrase.addEventListener('click', () => activate('passphrase'));
}

function setupEvents() {
  // Theme
  ui.themeToggle.addEventListener('click', toggleTheme);

  // Syncers
  ui.lengthRange.addEventListener('input', () => { syncLengthInputs(); savePasswordPrefs(); });
  ui.lengthNumber.addEventListener('input', () => { syncLengthInputs(); savePasswordPrefs(); });
  ui.wordsRange.addEventListener('input', () => { syncWordsInputs(); savePassphrasePrefs(); });
  ui.wordsNumber.addEventListener('input', () => { syncWordsInputs(); savePassphrasePrefs(); });

  // Password option changes trigger re-gen
  [ui.optLower, ui.optUpper, ui.optDigits, ui.optSymbols, ui.optExcludeSimilar, ui.optExcludeAmbiguous, ui.optNoAdjacent, ui.optGroup, ui.symbolsInput].forEach(el => {
    el.addEventListener('input', () => { savePasswordPrefs(); });
    el.addEventListener('change', () => { savePasswordPrefs(); });
  });

  ui.presetSelect.addEventListener('change', () => {
    applyPresetToUI(ui.presetSelect.value);
    generateAndRenderPassword();
  });

  ui.btnGeneratePassword.addEventListener('click', generateAndRenderPassword);
  ui.btnCopyPassword.addEventListener('click', () => {
    const raw = ui.passwordOutput.dataset.raw || ui.passwordOutput.value;
    copyText(raw);
  });
  ui.btnCopyPasswordFormatted.addEventListener('click', () => copyText(ui.passwordOutput.value));
  ui.btnTogglePassword.addEventListener('click', () => {
    // Toggle monospace blur for privacy (simple approach)
    ui.passwordOutput.style.filter = ui.passwordOutput.style.filter ? '' : 'blur(4px)';
  });

  ui.btnClearPasswordHistory.addEventListener('click', () => {
    writeJsonToLocalStorage(StorageKeys.passwordHistory, []);
    renderHistory('password');
  });

  // Passphrase
  [ui.sepInput, ui.capSelect, ui.optAddNumber, ui.optAddSymbol, ui.phraseSymbolsInput].forEach(el => {
    el.addEventListener('input', savePassphrasePrefs);
    el.addEventListener('change', savePassphrasePrefs);
  });

  ui.btnGeneratePassphrase.addEventListener('click', generateAndRenderPassphrase);
  ui.btnCopyPassphrase.addEventListener('click', () => copyText(ui.passphraseOutput.value));
  ui.btnClearPassphraseHistory.addEventListener('click', () => {
    writeJsonToLocalStorage(StorageKeys.passphraseHistory, []);
    renderHistory('passphrase');
  });
}

function init() {
  initTheme();
  setupTabs();
  loadPrefsIntoUI();
  syncLengthInputs();
  syncWordsInputs();
  renderHistory('password');
  renderHistory('passphrase');

  // Auto-generate on first load
  applyPresetToUI('strong');
  generateAndRenderPassword();
  generateAndRenderPassphrase();

  registerServiceWorker();
}

init();
