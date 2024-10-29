import XDurak from "./XDurak.js";

const runTime = new Date();
import { CheckBox, DialogBuilder, EditText, LayoutParams, LinearLayout, TextView, View } from './AndroidBasic.js';
import { Preferences } from "./GDX.js";
type HistoryType = {value: number,date: number};
function timeNow(date: Date) {
    return ((date.getHours() < 10)?"0":"") + date.getHours() +":"+ ((date.getMinutes() < 10)?"0":"") + date.getMinutes() +":"+ ((date.getSeconds() < 10)?"0":"") + date.getSeconds();
}
function today (date: Date) { 
    return ((date.getDate() < 10)?"0":"") + date.getDate() +"/"+(((date.getMonth()+1) < 10)?"0":"") + (date.getMonth()+1) +"/"+ date.getFullYear();
}
console.warn("work, runtime: ",today(runTime), timeNow(runTime));
class ModPreferences{
    public preferences: Preferences;
    constructor(instance: Java.Wrapper){
        this.preferences = new Preferences(instance);
        this.preferences.putString("version",XDurak.VERSION);
        this.preferences.flush();
    }
    accurate_search: number = 0;
    connect_to_first_game: boolean = false;
    public get auto_beat(): boolean {
        return this.preferences.getBoolean("auto_beat",false);
    }

    public set auto_beat(value: boolean) {
        this.preferences.putBoolean("auto_beat", value);
        this.preferences.flush();
    }


    public get auto_take(): boolean {
        return this.preferences.getBoolean("auto_take",false);
    }

    public set auto_take(value: boolean) {
        this.preferences.putBoolean("auto_take", value);
        this.preferences.flush();
    }

    public get auto_done(): boolean {
        return this.preferences.getBoolean("auto_done",false);
    }

    public set auto_done(value: boolean) {
        this.preferences.putBoolean("auto_done", value);
        this.preferences.flush();
    }

    public get watch_cards(): boolean {
        return this.preferences.getBoolean("watch_cards",false);
    }

    public set watch_cards(value: boolean) {
        this.preferences.putBoolean("watch_cards", value);
        this.preferences.flush();
    }

    public get auto_ready(): boolean {
        return this.preferences.getBoolean("auto_ready",false);
    }

    public set auto_ready(value: boolean) {
        this.preferences.putBoolean("auto_ready", value);
        this.preferences.flush();
    }

    public get highlight(): boolean {
        return this.preferences.getBoolean("highlight",true);
    }

    public set highlight(value: boolean) {
        this.preferences.putBoolean("highlight", value);
        this.preferences.flush();
    }


    public get toast_cheater(): boolean {
        return this.preferences.getBoolean("toast_cheater",true);
    }

    public set toast_cheater(value: boolean) {
        this.preferences.putBoolean("toast_cheater", value);
        this.preferences.flush();
    }

    public get grey_card_cheater(): boolean {
        return this.preferences.getBoolean("grey_card_cheater",true);
    }

    public set grey_card_cheater(value: boolean) {
        this.preferences.putBoolean("grey_card_cheater", value);
        this.preferences.flush();
    }

    public get autoclick_cheater(): boolean {
        return this.preferences.getBoolean("autoclick_cheater",false);
    }

    public set autoclick_cheater(value: boolean) {
        this.preferences.putBoolean("autoclick_cheater", value);
        this.preferences.flush();
    }

    public get match_history(): HistoryType[]{
        return JSON.parse(this.preferences.getString('match_history','[]'));
    }

    public set match_history(history: HistoryType[]){
        this.preferences.putString('match_history',JSON.stringify(history));
        this.preferences.flush();

    }



    public get smile(): string{
        return this.preferences.getString('smile','');
        
    }

    public set smile(value: string){
        this.preferences.putString('smile',value);
        this.preferences.flush();
    }

    public get shirt(): string{
        return this.preferences.getString('shirt','');
        
    }

    public set shirt(value: string){
        this.preferences.putString('shirt',value);
        this.preferences.flush();
    }

    public get frame(): string{
        return this.preferences.getString('frame','');
        
    }

    public set frame(value: string){
        this.preferences.putString('frame',value);
        this.preferences.flush();
    }

}
const suitMap: { [key: string]: string } = {
    '♥️': 'H', // Черви
    '♦️': 'D', // Бубны
    '♣️': 'C', // Трефы
    '♠️': 'S'  // Пики
};
function sortCards(cards: string[], trumpSuit: string) {
    const suitsOrder = ["♠", "♣", "♦", "♥"]; // порядок мастей
    const valuesOrder = ["2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"]; // порядок карт

    // Функция для получения индекса масти
    const getSuitIndex = (suit: string) => {
        return suit === trumpSuit ? Infinity : suitsOrder.indexOf(suit);
    };

    // Функция для получения индекса значения карты
    const getValueIndex = (value: string) => valuesOrder.indexOf(value);

    // Сортировка массива карт
    return cards.sort((a, b) => {
        const suitA = a[0];
        const suitB = b[0];
        const valueA = a.slice(1);
        const valueB = b.slice(1);

        // Сначала сортируем по мастям, козырная масть всегда последняя
        if (getSuitIndex(suitA) !== getSuitIndex(suitB)) {
            return getSuitIndex(suitA) - getSuitIndex(suitB);
        }

        // Если масти одинаковые, сортируем по значениям
        return getValueIndex(valueA) - getValueIndex(valueB);
    });
}
function formatSortedCards(cards: string[]): string {
    // Определяем объект, где ключи - масти, а значения - массивы карт
    const suits: { [key: string]: string[] } = {
        "♠": [],
        "♣": [],
        "♦": [],
        "♥": []
    };

    // Разделяем карты по мастям
    cards.forEach((card: string) => {
        const suit = card[0];
        const value = card.slice(1);
        suits[suit].push(value);
    });

    // Формируем текстовый вывод
    let result = "";
    Object.keys(suits).forEach((suit: string) => {
        if (suits[suit].length > 0) {
            result += `${suit}: ${suits[suit].join(" ")}\n`;
        }
    });

    return result.trim(); // Убираем последний перенос строки
}
// Функция для преобразования мастей
const normalizeSuit = (card: string) => {
    const regex = new RegExp(Object.keys(suitMap).join('|'), 'g');
    const result = card.replace(regex, match => suitMap[match]);
    const suit = getSuit(result);
    
    return suit; 
};

// Функция для определения масти карты
const getSuit = (card: string) => card.slice(0, 1);

// Функция для определения достоинства карты (с числом или фигурой)
const getRank = (card: string) => card.slice(1);

// Функция для получения числового значения достоинства карты
const rankValue = (rank: string) => {
    switch(rank) {
        case 'A': return 14; // Туз
        case 'K': return 13; // Король
        case 'Q': return 12; // Королева
        case 'J': return 11; // Валет
        default: return parseInt(rank, 10); // Числовые карты
    }
};

// Функция для сравнения карты и определения, может ли она побить
const canBeatCard = (cardInHand: string, cardOnTable: string, trumpSuit: string) => {
    const rankInHand = getRank(cardInHand);
    const suitInHand = normalizeSuit(cardInHand);
    const rankOnTable = getRank(cardOnTable);
    const suitOnTable = normalizeSuit(cardOnTable);

    // Сравниваем достоинства карт с учетом их числовых значений
    const valueInHand = rankValue(rankInHand);
    const valueOnTable = rankValue(rankOnTable);
    
    // Если масти одинаковые, сравниваем достоинства
    if (suitInHand === suitOnTable) {
        return valueInHand > valueOnTable;
    }

    // Если карта на столе козырная, то не можем побить обычной картой
    if (suitOnTable === normalizeSuit(trumpSuit)) {
        return false;
    }

    // Если карта на столе не козырная, а масть на руке козырная, то можем побить
    if (suitInHand === normalizeSuit(trumpSuit)) {
        return true;
    }

    // Если масти разные и не козырные, то не можем побить
    return false;
};
function canBeat(cardsInHand: string[], cardsOnTable: string[], trumpSuit: string) {
    const beatableCards: string[] = [];

    // Сопоставление мастей
    for (const cardOnTable of cardsOnTable) {
        for (const cardInHand of cardsInHand) {
            if (canBeatCard(cardInHand, cardOnTable, trumpSuit)) {
                if (!beatableCards.includes(cardInHand)) {
                    beatableCards.push(cardInHand);
                }
            }
        }
    }

    return beatableCards;
}
function getMatchingCards(hand: string[], table: string[]) {
    const valuesOnTable = table.map(card => card.slice(-1)); // Получаем значения карт на столе
    return hand.filter(card => valuesOnTable.includes(card.slice(-1))); // Фильтруем карты в руке
}
function optimalBeatOrder(cardsInHand: string[], cardsOnTable: string[], trumpSuit: string) {
    // Массив для хранения результата в формате {orig, beat}
    const optimalOrder: { orig: string, beat: string }[] = [];
    
    // Сортируем карты в руке сначала по козырям, затем по старшинству, чтобы подбирать минимально сильные карты
    cardsInHand.sort((a, b) => {
        const suitA = normalizeSuit(a) === trumpSuit ? 1 : 0;
        const suitB = normalizeSuit(b) === trumpSuit ? 1 : 0;
        const rankA = rankValue(getRank(a));
        const rankB = rankValue(getRank(b));

        if (suitA !== suitB) return suitB - suitA; // Козыри идут первыми
        return rankA - rankB; // Обычные карты сортируются по старшинству
    });

    // Пробуем побить каждую карту на столе
    for (const cardOnTable of cardsOnTable) {
        let cardFound = false;

        for (let i = 0; i < cardsInHand.length; i++) {
            const cardInHand = cardsInHand[i];

            // Проверка, может ли карта в руке побить карту на столе
            if (canBeatCard(cardInHand, cardOnTable, trumpSuit)) {
                // Добавляем объект с картой на столе и бьющей картой в оптимальный порядок и удаляем карту из руки
                optimalOrder.push({ orig: cardOnTable, beat: cardInHand });
                cardsInHand.splice(i, 1);
                cardFound = true;
                break;
            }
        }

        // Если для текущей карты на столе нет карты для побития, возвращаем пустой список
        if (!cardFound) {
            return [];
        }
    }

    return optimalOrder;
}

class MatchData{
    discard_cards: string[] = [];
    enemy_known_cards: Array<string[]> = [[],[],[],[],[],[]];
    id: number;
    enemy_hand_cards: string[] = [];
    final_enemy_hand: boolean = false;
    cards_on_table: string[] = [];
    cards_on_table_bito: string[] = [];
    cards_on_table_active: string[] = [];
    constructor(id: number){
        this.id = id;
    }
}

let mpf: ModPreferences;
Java.perform(() => {
    let matchData = new MatchData(0);
    try {
        Java.choose("com.rstgames.durak.StartActivity", {
            onComplete(){},
            onMatch(instance){
                if (instance == null) return;
                if (instance.getPreferences !== undefined){
                    mpf = new ModPreferences(instance.getPreferences("XDurak"));
                    return 'stop'

                }
            }
        })
    } catch {}


    const JGdx = Java.use('com.badlogic.gdx.Gdx');
    const StartActivity = Java.use("com.rstgames.durak.StartActivity");
    const auth_cancel_handler = Java.use("com.rstgames.durak.StartActivity$b");
    const TCPServer = Java.use("com.rstgames.net.f");
    const GameController = Java.use("com.rstgames.b");
    const Screen = Java.use("com.badlogic.gdx.Screen");
    const Game = Java.use("com.badlogic.gdx.Game");
    const ScreenUtils = Java.use("com.badlogic.gdx.utils.ScreenUtils");
    const Group = Java.use("com.badlogic.gdx.scenes.scene2d.Group");
    const Settings = Java.use("com.rstgames.uiscreens.q");
    const Graphics = Java.use("com.badlogic.gdx.Graphics");
    const k = Java.use("com.rstgames.durak.screens.CreateGameScreen$k")
    const ScreenViewport = Java.use("com.badlogic.gdx.utils.viewport.ScreenViewport");
    const Stage = Java.use("com.badlogic.gdx.scenes.scene2d.Stage");
    const a0 = Java.use("com.rstgames.utils.a0");
    const AppController = Java.use("com.rstgames.AppController");
    const Label = Java.use("com.badlogic.gdx.scenes.scene2d.ui.Label");
    const LabelStyle = Java.use("com.badlogic.gdx.scenes.scene2d.ui.Label$LabelStyle");
    const JString = Java.use("java.lang.String")
    const GDXColor = Java.use("com.badlogic.gdx.graphics.Color");
    const BitmapFont = Java.use("com.badlogic.gdx.graphics.g2d.BitmapFont");
    const c = Java.use("com.rstgames.durak.screens.c");
    const JColor = Java.use('android.graphics.Color');
    const InputEvent = Java.use("com.badlogic.gdx.scenes.scene2d.InputEvent");
    const JoinToGameClickListener = Java.use("com.rstgames.durak.screens.c$e$a");
    const ListPublicGames = Java.use("com.rstgames.durak.screens.c");
    const Logger = Java.use("com.badlogic.gdx.utils.Logger");
    const SearchController = Java.use("com.rstgames.durak.controllers.a");
    const b0 = Java.use("com.rstgames.utils.b0");
    const RSTAssetPosition = Java.use("com.rstgames.utils.RSTAssetPosition");
    let ASSET_STATE = Java.use("com.rstgames.utils.RSTAssetPosition$ASSET_STATE");
    const MoreGames = Java.use("com.rstgames.uiscreens.m");
    const textLabel = Java.use("com.rstgames.utils.a0");
    const ClickListener = Java.use("com.badlogic.gdx.scenes.scene2d.utils.ClickListener");
    const ListPrivateGames = Java.use("com.rstgames.durak.screens.d");
    const Texture = Java.use("com.badlogic.gdx.graphics.Texture");
    const TextureRegionDrawable = Java.use("com.badlogic.gdx.scenes.scene2d.utils.TextureRegionDrawable");
    const Image = Java.use("com.badlogic.gdx.scenes.scene2d.ui.Image");
    const MatchScreen = Java.use("com.rstgames.durak.screens.b");
    const MainScreen = Java.use("com.rstgames.uiscreens.l");
    const SearchFilter = Java.use("com.rstgames.durak.screens.a");
    const discard_packet_handler = Java.use("com.rstgames.durak.screens.b$x0");
    const g_packet_handler = Java.use("com.rstgames.durak.screens.c$e");
    const game_packet_handler = Java.use("com.rstgames.durak.screens.b$i");
    const JSONObject = Java.use("org.json.b");
    const JSONArray = Java.use("org.json.a");
    const DiscardClickListener = Java.use("com.rstgames.durak.utils.a$c");
    const JsonIpServerConnector = Java.use("com.rstgames.net.JsonIpServerConnector");
    const features_handler = Java.use("com.rstgames.durak.screens.b$j");
    const enemy_pickup_card_animate_l = Java.use("com.rstgames.durak.screens.b$o0$l");
    const enemy_pickup_card_animate_a = Java.use("com.rstgames.durak.screens.b$o0$a");
    const animate_t = Java.use("com.rstgames.durak.screens.b$p0$a");
    const animate_b_c_card = Java.use("com.rstgames.durak.screens.b$s0$a");
    const d0 = Java.use("com.rstgames.durak.screens.b$d0");
    const o0 = Java.use("com.rstgames.durak.screens.b$f0");
    const GAME_STATE = Java.use("com.rstgames.durak.controllers.GameController$GAME_STATE");
    const utils_4_cards = Java.use("com.rstgames.durak.utils.d");
    const end_turn_handler = Java.use("com.rstgames.durak.screens.b$o0");
    const mode_handler = Java.use("com.rstgames.durak.screens.b$m0");
    const j0 = Java.use("com.rstgames.durak.screens.b$j0");
    const win_handler = Java.use("com.rstgames.durak.screens.b$g1");
    const Toast = Java.use("android.widget.Toast");
    const CARD_VIEW_TYPE = Java.use("com.rstgames.durak.utils.Card$CARD_VIEW_TYPE");
    const ShopAssets = Java.use("com.rstgames.uiscreens.d");

    function show_menu(){
        Java.scheduleOnMainThread(() => {
            const startActivity = Java.cast(JGdx.app.value,StartActivity);
            const gameController = Java.cast(startActivity.getApplicationListener(),GameController);
            const classname = gameController.getScreen().$className;
            if (classname == "com.rstgames.durak.screens.a") {
                const searchDialog = new DialogBuilder(startActivity);
                const searchInput = new EditText(startActivity,"","Нужная ставка");
                searchDialog.setTitle("Точный поиск");
                searchDialog.setView(searchInput);
                searchDialog.setPositiveButton("Применить",(d,w) => {
                    mpf.accurate_search = Number(searchInput.getText());
                });
                searchDialog.setNegativeButton("Сбросить",(d,w) => {
                    mpf.accurate_search = 0;
                });
                if (mpf.accurate_search > 0){
                    searchInput.setText(mpf.accurate_search.toString());
                }
                searchDialog.show();
            } else if (classname == "com.rstgames.durak.screens.c") {
                const connectToFirstGameDialog = new DialogBuilder(startActivity);
                connectToFirstGameDialog.setTitle("Подключиться к первой новой игре?")
                if (mpf.connect_to_first_game){
                    connectToFirstGameDialog.setMessage("(Включено)")
                } else {
                    connectToFirstGameDialog.setMessage("(Выключено)")
                }
                connectToFirstGameDialog.setPositiveButton("Да",(c,w) => {
                    mpf.connect_to_first_game = true;
                })
                connectToFirstGameDialog.setNegativeButton("Нет",(c,w) => {
                    mpf.connect_to_first_game = false;
                })
                connectToFirstGameDialog.show();
            } else if (classname == "com.rstgames.durak.screens.b") {
                const matchScreen = gameController._N.value;
                const matchController = matchScreen._w.value;
                const cardsController = matchScreen._x.value;
                const ch = matchController.j?.value ?? false;

                const settingsDialogB = new DialogBuilder(startActivity);
                const layout = new LinearLayout(startActivity);
                const watch_cards_checkbox = new CheckBox(startActivity,"Просмотр карт (Заменяет просмотр профиля)",mpf.watch_cards);
                const highlight_checkbox = new CheckBox(startActivity, "Подсвечивать карты", mpf.highlight);
                const auto_category = new TextView(startActivity,"Автоматизация: ");
                const auto_ready_checkbox = new CheckBox(startActivity,"Автоматически подтверждать игру",mpf.auto_ready);
                const auto_done_checkbox = new CheckBox(startActivity,"Автоматически заканчивать Пас/Готов, если нет карт",mpf.auto_done);
                const auto_take_checkbox = new CheckBox(startActivity,"Автоматически подбирать карты, если нет карт", mpf.auto_take);
                const auto_beat_checkbox = new CheckBox(startActivity,"Автоматически отбиваться, если есть карты", mpf.auto_beat);
                watch_cards_checkbox.setCheckedChangeListener((b,isChecked) => {
                    mpf.watch_cards = isChecked;
                });
                highlight_checkbox.setCheckedChangeListener((b,isChecked) => {
                    mpf.highlight = isChecked;
                });
                auto_ready_checkbox.setCheckedChangeListener((b, isChecked) => {
                    mpf.auto_ready = isChecked;
                });
                auto_done_checkbox.setCheckedChangeListener((b, isChecked) => {
                    mpf.auto_done = isChecked;
                });
                auto_take_checkbox.setCheckedChangeListener((b, isChecked) => {
                    mpf.auto_take = isChecked;
                });
                auto_beat_checkbox.setCheckedChangeListener((b, isChecked) => {
                    mpf.auto_beat = isChecked;
                });
                layout.setOrientation("VERTICAL");
                layout.addViews([watch_cards_checkbox,highlight_checkbox,auto_category,auto_ready_checkbox,auto_done_checkbox,auto_take_checkbox]);
                if (ch) {
                    const cheater_category = new TextView(startActivity, "Шулер: ")
                    const toast_cheater_checkbox = new CheckBox(startActivity, "Отображать сообщение о шулере",mpf.toast_cheater);
                    toast_cheater_checkbox.setCheckedChangeListener((b,isChecked) => {
                        mpf.toast_cheater = isChecked;
                    });
                    const grey_card_cheater_checkbox = new CheckBox(startActivity, "Помечать серым нечестную карту",mpf.grey_card_cheater);
                    grey_card_cheater_checkbox.setCheckedChangeListener((b,isChecked) => {
                        mpf.grey_card_cheater = isChecked;
                    });
                    const autoclick_cheater_checkbox = new CheckBox(startActivity, "Автоматически нажимать на нечестную карту",mpf.autoclick_cheater);
                    autoclick_cheater_checkbox.setCheckedChangeListener((b,isChecked) => {
                        mpf.autoclick_cheater = isChecked;
                    });
                    layout.addViews([cheater_category,toast_cheater_checkbox,grey_card_cheater_checkbox,autoclick_cheater_checkbox]);
                };
                settingsDialogB.setTitle("Настройки матча");
                settingsDialogB.setView(layout);
                settingsDialogB.setPositiveButton("OK",(d,w) => {});
                settingsDialogB.show();
                // mpf.watch_cards = !mpf.watch_cards;
                // Toast.makeText(startActivity,JString.$new(mpf.watch_cards ? "Просмотр карт" : "Просмотр профиля"), Toast.LENGTH_SHORT.value).show();
                // const known_cards = new DialogBuilder(startActivity);
                // known_cards.setTitle(matchData.enemy_hand_cards.length > 0 ? "Карты противника:" : "Известные карты:");
                // known_cards.setMessage(matchData.enemy_hand_cards.length > 0 ? matchData.enemy_hand_cards.join(" - ") : matchData.enemy_known_cards.join(" - "));
                // known_cards.show();
            } else if (classname == "com.rstgames.uiscreens.d") {
                const skinSettingsDialogB = new DialogBuilder(startActivity);
                const layout = new LinearLayout(startActivity); layout.setOrientation("VERTICAL");
                const desc = new TextView(startActivity,"Введите id скина в правильном поле или оставьте пустым, чтобы не заменять.\nВсе изменения видны только вам.")
                const smile_editText = new EditText(startActivity, mpf.smile, "smile_classic");
                const shirt_editText = new EditText(startActivity, mpf.shirt, "shirt_classic");
                const frame_editText = new EditText(startActivity, mpf.frame, "frame_classic");
                layout.addViews([desc,smile_editText,shirt_editText,frame_editText]);
                skinSettingsDialogB.setTitle("Скинченджер");
                skinSettingsDialogB.setView(layout);
                skinSettingsDialogB.setPositiveButton("OK",()=>{
                    const tcpServer = gameController._d.value;
                    mpf.smile = smile_editText.getText();
                    mpf.shirt = shirt_editText.getText();
                    mpf.frame = frame_editText.getText();
                    const json = JSONObject.$new();
                    json.N("v",mpf.frame);
                    json.N("k","frame")
                    tcpServer.h("uu", json)
                });
                skinSettingsDialogB.show();
            }
        })
    }

    Game["setScreen"].implementation = function (screen: Java.Wrapper) {
        if (mpf !== undefined){
            mpf.connect_to_first_game = false; // отключение функции для избежания ошибок 
        }
        this["setScreen"](screen);
    };

    // функция для получения минимальной ставки
    SearchController["b"].implementation = function () {
        let result = this["b"]();
        if (mpf.accurate_search > 0){result = mpf.accurate_search} // замена мин и макс ставки для точного поиска
        return result;
    };
    // функция для получения максимальной ставки
    SearchController["e"].implementation = function () {
        let result = this["e"]();
        if (mpf.accurate_search > 0){result = mpf.accurate_search} // замена мин и макс ставки для точного поиска
        return result;
    };

    function inject_mod_menu(this: Java.Wrapper) {
        this["show"]();
        const app = JGdx.app.value;
        const files = JGdx.files.value;
        const graphics = JGdx.graphics.value;
        const gameController = Java.cast(app.getApplicationListener(), GameController);
        const stageInstance = gameController.a0.value;

        // Создаем текстуру кнопки
        const buttonTexture = Texture.$new(files.internal("data/general_textures/achieves_and_assets/cheat_success/icon.png"), true);
        const button = Image.$new(buttonTexture);
        button.setPosition(10, graphics.getHeight() - button.getHeight() - 10);
        button.setSize(button.getWidth() / 1.5, button.getHeight() / 1.5);

        // Обработчик клика для кнопки
        button.addListener(Java.registerClass({
            name: "com.triggeroff.frida.FiltersOnClick",
            superClass: ClickListener,
            methods: {
                clicked: {
                    returnType: 'void',
                    argumentTypes: ['com.badlogic.gdx.scenes.scene2d.InputEvent', 'float', 'float'],
                    implementation(a, b, c) {
                        show_menu();
                    }
                }
            }
        }).$new());

        // Добавляем кнопку на сцену
        stageInstance.addActor(button);

    }
    
    StartActivity["onCreate"].implementation = function (bundle: Java.Wrapper) {
        mpf = new ModPreferences(this.getPreferences("XDurak"));
        this["onCreate"](bundle);
    };
    StartActivity["p"].implementation = function (click_handler: Java.Wrapper, header: string, positive: string, negative: string, cancelable: boolean) {
        if (click_handler.$className == "com.rstgames.durak.StartActivity$b") {
            header = "Способ входа:";
            negative = "Токен";
            positive = "Гугл";
        }
        this["p"](click_handler, header, positive, negative, cancelable);
    };
    // Negative | Выйти | Токен
    auth_cancel_handler["b"].implementation = function (this: Java.Wrapper) { 
        const startActivity = this._a.value;
        const dialog = new DialogBuilder(startActivity);
        const edittext = new EditText(startActivity);
        const gameController = startActivity._a.value;
        edittext.setHint("Токен");
        dialog.setTitle("Введите токен");
        dialog.setView(edittext);
        dialog.setPositiveButton("ОК", (dialog,which) => {
            const token = edittext.getText();
            startActivity["A"](token); // сохранение токена в shared preferences
            if (gameController != null) {
                const tcpServer = gameController._d?.value;
                if (tcpServer != null || tcpServer != undefined) {
                    tcpServer._w.value = token; // сохранение токена в нынешней сессии 
                    tcpServer.u(false); // авторизация
                }
            }
        })
        dialog.show();
    };

    Logger["info"].overload('java.lang.String').implementation = function (str: string) {
        // console.log(str);
             
        this["info"](str);
    };


    let MainScreenAvatarClickListener = Java.use("com.rstgames.utils.b0$a");
    MainScreenAvatarClickListener["clicked"].implementation = function (inputEvent: Java.Wrapper, f: number, f2: number) {
        this["clicked"](inputEvent, f, f2);
        Java.scheduleOnMainThread(() => {
            const startActivity = JGdx.app.value;
            const dialogb = new DialogBuilder(startActivity);
            dialogb.setTitle("История матчей");
            let textmsg = '';
            mpf.match_history.sort((a, b) => b.date - a.date).forEach((match) => {
                let matchdate = new Date(match.date);
                textmsg += `${today(matchdate)} ${timeNow(matchdate)} ${match.value > 0 ? '+'+match.value.toString() : match.value}\n`;
            });
            dialogb.setMessage(textmsg);
            dialogb.setPositiveButton("Очистить историю", (d,w) => {
                mpf.match_history = [];
            });
            dialogb.setNegativeButton("Закрыть", (d,w) => {
                
            })
            dialogb.show();
        });
    };

    // добавление на экраны кнопки мод меню

    // MainScreen["show"].implementation = inject_mod_menu;
    SearchFilter["show"].implementation = inject_mod_menu;
    ListPublicGames["show"].implementation = inject_mod_menu;
    MatchScreen["show"].implementation = inject_mod_menu;
    ShopAssets["show"].implementation = inject_mod_menu;
    
    // обработка пакета "g"
    g_packet_handler["a"].implementation = function (this:Java.Wrapper,str: string, jSONObject: Java.Wrapper) {
        this["a"](str, jSONObject);
        if (mpf.connect_to_first_game) {
            const clickListener = JoinToGameClickListener.$new(this,jSONObject);
            clickListener.clicked(InputEvent.$new(),0,0);
            mpf.connect_to_first_game = false;
        }
        
    };

    // получение данных о матче
    game_packet_handler["a"].implementation = function (str: string, jSONObject: Java.Wrapper) {
        matchData = new MatchData(jSONObject.g('id'));
        // const players = jSONObject.B("players");
        // for (let i = 0; i < players; i++) {
        //     matchData.enemy_known_cards[i] = [];
        // }
        this["a"](str, jSONObject);
    };

    DiscardClickListener["clicked"].implementation = function (inputEvent: Java.Wrapper, f: number, f2: number) {
        this["clicked"](inputEvent, f, f2);
        const net_instance = this.a.value._a.value.E(); // TCPServer
        const discard_json = JSONObject.$new();
        const discard_array = JSONArray.$new();
        matchData.discard_cards.forEach((e) => {
            discard_array['x'](e); // .push
        });
        discard_json.N("c",discard_array);
        net_instance["h"]("discard",discard_json);
    };

    JsonIpServerConnector["o"].implementation = function (str: string) {
        if (str === "show_discard") {
            // блокировка отправки пакета на покупку отображения битых карт
            return
        }
        this["o"](str);
    };

    //обработка пакета "features"
    features_handler["a"].implementation = function (str: string, jSONObject: Java.Wrapper) {
        // редактирование цен на 0
        jSONObject.L("dis",0);
        jSONObject.L("hl",0);
        this["a"](str, jSONObject);
    };
    
    function enemy_pickup_card_animate(this: Java.Wrapper){
        const matchScreen = this.c.value._a.value;
        const card_index = this.a.value;
        const place_id = this.b.value;
        matchData.enemy_known_cards[place_id].push(matchScreen._W.value[this.a.value]._c.value);        
        this["run"]();
    }

    // function enemy_drop_card_animate(this: Java.Wrapper){
    //     const matchScreen = this.c.value._a.value;
    //     const card_index = this.a.value;
    //     const all_cards = matchScreen._W.value;
    //     const card = all_cards[card_index];
    //     matchData.enemy_known_cards[place_index] = matchData.enemy_known_cards[place_index].filter((value) => value !== card._c.value);
    //     this["run"]();
    // }

    enemy_pickup_card_animate_l["run"].implementation = enemy_pickup_card_animate;
    enemy_pickup_card_animate_a["run"].implementation = enemy_pickup_card_animate;
    function enemy_drop_card_handler(this:Java.Wrapper,str: string, jSONObject: Java.Wrapper) {
        this["a"](str, jSONObject);
        let card_string_name = jSONObject.H("c");
        const matchScreen = this._a.value;
        const matchController = matchScreen._w.value;
        const ch = matchController.j.value;
        const card_string_name_b = jSONObject.H("b");
        const cardsController = matchScreen._x.value;
        const trump = cardsController._i.value;
        const startActivity = JGdx.app.value;
        const all_cards = matchScreen._W.value;
        let card_legal = false;
        if (ch) {
            if (matchData.cards_on_table.length > 0) {
                matchData.cards_on_table.forEach((card) => {
                    if (getRank(card) == getRank(card_string_name)) {
                        card_legal = true;
                    }
                });
            } else {
                card_legal = true;
            }
        }
        if (card_string_name_b != "") {
            if (ch) {
                card_legal = canBeatCard(card_string_name_b,card_string_name,trump);
            }
            card_string_name = card_string_name_b
        }
        if (!card_legal && ch) {
            Java.scheduleOnMainThread(() => {
                if (mpf.toast_cheater) Toast.makeText(startActivity,JString.$new("шулер"), Toast.LENGTH_SHORT.value).show();
                const card = all_cards[matchScreen['u'](card_string_name)];
                if (mpf.grey_card_cheater) card.d(CARD_VIEW_TYPE.c.value);
            });
        }
        const place_id = jSONObject.B("id");
        matchData.enemy_known_cards[place_id] = matchData.enemy_known_cards[place_id].filter((value) => value !== card_string_name);
    };
    // animate_t["run"].implementation = enemy_drop_card_animate;
    // animate_b_c_card["run"].implementation = enemy_drop_card_animate;
    let b_handler = Java.use("com.rstgames.durak.screens.b$s0");
    b_handler["a"].implementation = enemy_drop_card_handler;
    let tfs_handler = Java.use("com.rstgames.durak.screens.b$p0");
    tfs_handler["a"].implementation = enemy_drop_card_handler;
    // обработка пакета "end_turn"
    end_turn_handler["a"].implementation = function (str: string, jSONObject: Java.Wrapper) {
        this["a"](str, jSONObject);
        matchData.cards_on_table_bito = [];

    };

    // анимация битья карты
    utils_4_cards["g"].implementation = function (orig_card: string, bitaya_card: string, z: boolean): Java.Wrapper {
        if (bitaya_card != "" && orig_card != "sw") {
            matchData.cards_on_table_bito.push(orig_card,bitaya_card)
        }
        const result = this["g"](orig_card, bitaya_card, z);
        return result;
    };

    // функция для подсветки карт
    function highlight(matchScreen: Java.Wrapper){
        const cards_list = matchScreen._W.value;
        matchData.cards_on_table = [];
        const hand_cards: string[] = [];
        if (cards_list != null ) {
            cards_list.forEach((element: Java.Wrapper) => {
                if (element.g.value == 2) {
                    matchData.cards_on_table.push(element._c.value);
                } else if (element.g.value == 1){
                    hand_cards.push(element._c.value);
                }
            });
        }

        
        matchData.cards_on_table_active = matchData.cards_on_table.filter(item => !matchData.cards_on_table_bito.includes(item));
        const gameController = matchScreen._a.value;
        const matchController = matchScreen._w.value;
        const cardsController = matchScreen._x.value;
        const trump = cardsController._i.value;        
        const my_place_id: number = matchController.z.value;
        const players_mode_list: number[] = matchController.p.value;
        const hl_json = JSONObject.$new();
        const c_jsonArray = JSONArray.$new();
        const sw = matchController.k.value;
        // console.log("active: ",matchData.cards_on_table_active);
        // console.log("bito: ",matchData.cards_on_table_bito);
        // console.log("table: ",matchData.cards_on_table);
        // console.log("hand: ",hand_cards.filter(element => element != null));
        if (mpf.highlight) {
            if (players_mode_list[my_place_id] == 9) {
                let matchingCards: string[] = [];
                const canBeatCards = canBeat(hand_cards.filter(element => element != null), matchData.cards_on_table_active, trump);
                canBeatCards.forEach((e) => {
                    c_jsonArray.x(e)
                });
                if (sw && matchData.cards_on_table_bito.length == 0) {
                    matchingCards = getMatchingCards(hand_cards.filter(element => element != null), matchData.cards_on_table);
                    matchingCards.forEach((e) => {
                        c_jsonArray.x(e)
                    })
                }

                hl_json.N("c", c_jsonArray)
            } else if (players_mode_list[my_place_id] == 0 || players_mode_list[my_place_id] == 1 && matchData.cards_on_table.length > 0) {
                const matchingCards = getMatchingCards(hand_cards.filter(element => element != null), matchData.cards_on_table);
                matchingCards.forEach((e) => {
                    c_jsonArray.x(e)
                });
                hl_json.N("c", c_jsonArray)
            }
                
        };
        gameController.E().h('hl',hl_json);
    }

    // обработка пакета "mode"
    mode_handler["a"].implementation = function (str: string, jSONObject: Java.Wrapper) {
        this["a"](str, jSONObject);
        const matchScreen = this._a.value;
        highlight(matchScreen);

        const cards_list = matchScreen._W.value;
        matchData.cards_on_table = [];
        const hand_cards: string[] = [];
        
        if (cards_list != null ) {
            cards_list.forEach((element: Java.Wrapper) => {
                if (element.g.value == 2) {
                    matchData.cards_on_table.push(element._c.value);
                } else if (element.g.value == 1){
                    hand_cards.push(element._c.value);
                }
            });
        }

        
        matchData.cards_on_table_active = matchData.cards_on_table.filter(item => !matchData.cards_on_table_bito.includes(item));
        const gameController = matchScreen._a.value;
        const matchController = matchScreen._w.value;
        const d_utils = matchController.G.value;
        const cardsController = matchScreen._x.value;
        const trump = cardsController._i.value;        
        const my_place_id: number = matchController.z.value;
        const players_mode_list: number[] = matchController.p.value;
        const sw = matchController.k.value;
        let matchingCards: string[] = [];
        if (players_mode_list[my_place_id] == 9) {
            const beatOrder = optimalBeatOrder(hand_cards,matchData.cards_on_table_active,trump);
            console.log(JSON.stringify(beatOrder));
            if (sw && matchData.cards_on_table_bito.length == 0) {
                matchingCards = getMatchingCards(hand_cards.filter(element => element != null), matchData.cards_on_table);
            }
            if (beatOrder.length == 0 && mpf.auto_take && matchingCards.length == 0) {
                gameController.E().o("take");
            }
            
        } else if (players_mode_list[my_place_id] == 0 || players_mode_list[my_place_id] == 1 && matchData.cards_on_table.length > 0) {
            const matchingCards = getMatchingCards(hand_cards.filter(element => element != null), matchData.cards_on_table);
            if (matchingCards.length == 0 && mpf.auto_done) {
                switch (players_mode_list[my_place_id]) {
                    case 0:
                        gameController.E().o("pass");
                        break
                    case 1:
                        gameController.E().o("done");
                        break
                }
            }
        }


    }
    j0["a"].implementation = function (i: number) {
        console.log(`j0.a is called: i=${i}`);
        this["a"](i);
    };
    // анимация и отправка пакета "t"
    j0["b"].implementation = function (i: number) {
        this["b"](i);
        highlight(this.i.value);
    };

    // функция для обновления всех элементов на экране матча, вызывается при получении почти каждого пакета с сервера
    MatchScreen["Q"].implementation = function () {
        const mod_shirt = mpf.shirt;
        if (mod_shirt != "") this.C0.value = mod_shirt;
        this["Q"]();
        const matchController = this._w?.value;
        const cardsController = this._x?.value;
        const gameController = this._a?.value;
        if (cardsController == null || matchController == null) {
            return
        }
        if (cardsController.o?.value) {
            matchData.discard_cards = cardsController.o?.value;
        }

        
        const cards_list = this._W.value;
        const players_count = cardsController._g.value.length;
        const trump = cardsController._i.value;
        const deck_have_cards_count = cardsController?._j.value;
        matchData.cards_on_table = [];
        const hand_cards: string[] = [];
        if (cards_list != null ) {
            cards_list.forEach((element: Java.Wrapper) => {
                if (element.g.value == 2) {
                    matchData.cards_on_table.push(element._c.value);
                } else if (element.g.value == 1){
                    hand_cards.push(element._c.value);
                }
            });
        }
        if (Number(deck_have_cards_count) == Number(0) && trump != "" && Number(players_count) == Number(2)) {
            const allCardsStr: string[] = [];
            cards_list.forEach((e: Java.Wrapper) => {
                allCardsStr.push(e._c.value);
            });
            const exclusionList = [...matchData.discard_cards,...hand_cards, ...matchData.cards_on_table , 'sw']
            const filteredList = allCardsStr.filter(item => !exclusionList.includes(item));
            matchData.enemy_hand_cards = filteredList;
            if (!matchData.final_enemy_hand) {
                matchData.final_enemy_hand = true;
                Java.scheduleOnMainThread(() => {
                    const startActivity = JGdx.app.value;
                    const hand_cards = new DialogBuilder(startActivity);
                    hand_cards.setTitle("Карты противника: ");
                    hand_cards.setMessage(formatSortedCards(sortCards(matchData.enemy_hand_cards,getSuit(trump))));
                    hand_cards.show();
                });
            }
        }
    };

    // функция для обработки пакета "win"
    win_handler["a"].implementation = function (str: string, jSONObject: Java.Wrapper) {
        this["a"](str, jSONObject);
        const matchScreen = this._a.value;
        const matchController = matchScreen._w.value;
        if (jSONObject.B("id") == matchController.z.value) { // если id победившего == id локального игрока
            const history: HistoryType[] = mpf.match_history;
            history.push({date: Date.now(), value: jSONObject.B("value")});
            mpf.match_history = history;
        }
    };

    let k0 = Java.use("com.rstgames.durak.screens.b$k0");
    k0["$init"].implementation = function (w, i, str) {
        this["$init"](w,i, str);
        const instance = Java.retain(this);
        if (mpf.autoclick_cheater) {
            setTimeout(() => {
                Java.perform(() => {
                    instance.clicked(InputEvent.$new(),0,0); // автоматическое обнаружение шулера
                })
            },100);
        }
    };

    let RSTGamePlaceOnClick = Java.use("com.rstgames.durak.utils.RSTGamePlace$a");
    let PLACE_TYPE = Java.use("com.rstgames.durak.utils.RSTGamePlace$PLACE_TYPE");
    RSTGamePlaceOnClick["clicked"].implementation = function (inputEvent: Java.Wrapper, f: number, f2: number) {
        const rstGamePlace = this.a.value; 
        const gameController = rstGamePlace._a.value;
        const matchScreen = gameController._N.value;
        const matchController = matchScreen._w.value;
        const my_place_id: number = matchController.z.value;
        const place_id = rstGamePlace.H.value;
        const startActivity = JGdx.app.value;
        const cardsController = matchScreen._x.value;
        const cards_list = matchScreen._W.value;
        matchData.cards_on_table = [];
        const hand_cards: string[] = [];
        if (cards_list != null ) {
            cards_list.forEach((element: Java.Wrapper) => {
                if (element.g.value == 2) {
                    matchData.cards_on_table.push(element._c.value);
                } else if (element.g.value == 1){
                    hand_cards.push(element._c.value);
                }
            });
        }
        const trump = cardsController._i.value;
        const place_type = rstGamePlace.G.value;    
        if (!mpf.watch_cards || place_type.toString() != PLACE_TYPE.c.value.toString()) {
            this["clicked"](inputEvent, f, f2);
            return
        }
        


        Java.scheduleOnMainThread(() => {
            const known_cards = new DialogBuilder(startActivity);
            known_cards.setTitle("Карты противника");
            let all_known_cards: string[] = [...matchData.discard_cards, ...hand_cards, ...matchData.cards_on_table, "sw"];
            matchData.enemy_known_cards.forEach((player) => {
                all_known_cards = [...all_known_cards, ...player]
            });
            const cards_list = matchScreen._W.value;
            const allCardsStr: string[] = [];
            cards_list.forEach((e: Java.Wrapper) => {
                allCardsStr.push(e._c.value);
            });
            const unknown_cards = allCardsStr.filter(item => !all_known_cards.includes(item));
            known_cards.setMessage(!matchData.final_enemy_hand ? "Известные карты:\n" + formatSortedCards(sortCards(matchData.enemy_known_cards[place_id],getSuit(trump))) + "\nНеизвестные карты:\n" + formatSortedCards(sortCards(unknown_cards,getSuit(trump)))  : formatSortedCards(sortCards(matchData.enemy_hand_cards,getSuit(trump))));
            known_cards.show();
        });
    };
    let btn_ready_on_handler = Java.use("com.rstgames.durak.screens.b$y");
    btn_ready_on_handler["a"].implementation = function (str: string, jSONObject: Java.Wrapper) {
        this["a"](str, jSONObject);
        const matchScreen = this._a.value;
        const gameController = matchScreen._a.value;
        if (mpf.auto_ready) gameController.E().o("ready");
    };

    // загрузка текстур для меню смайлов
    MatchScreen["V"].implementation = function () {
        const gameController = this._a.value;
        const tcpServer = gameController.E();
        if (mpf.smile != ""){
            tcpServer.P.value = mpf.smile;
        };
        this["V"]();
    };

    let smile_handler = Java.use("com.rstgames.durak.screens.b$r");
    smile_handler["a"].implementation = function (str: string, jSONObject: Java.Wrapper) {
        const mod_smile = mpf.smile;
        const place_id = jSONObject.B("p");
        const matchScreen = this._a.value;
        const matchController = matchScreen._w.value;
        if (place_id == matchController.z.value && mod_smile != "") jSONObject.N("a",mod_smile); 
        this["a"](str, jSONObject);
    };

    b0["n"].implementation = function (frame_id: string) {
        console.log(`b0.n is called: str=${frame_id}`);

        const mod_frame = mpf.frame;
        if (mod_frame != "") frame_id = mod_frame;
        this["n"](frame_id);
    };
    let RSTGamePlace = Java.use("com.rstgames.durak.utils.RSTGamePlace");
    RSTGamePlace["h"].implementation = function (str: string, str2: string, frame_id: string, str4: string, player_id: number, j2: number, i: number, z: boolean, group: Java.Wrapper, image: Java.Wrapper) {
        const mod_frame = mpf.frame;
        const gameController = this._a.value;
        const tcpServer = gameController._d.value;
        const my_player_id = tcpServer.c0.value; 
        if (player_id.valueOf() == my_player_id.valueOf() && mod_frame != "") frame_id = mod_frame
        this["h"](str, str2, frame_id, str4, player_id, j2, i, z, group, image);
    };
    let cp_handler = Java.use("com.rstgames.durak.screens.b$l");
    cp_handler["a"].implementation = function (str: string, jSONObject: Java.Wrapper) {
        const mod_shirt = mpf.shirt
        const shirt_json = jSONObject.E("shirt");
        if (mod_shirt != "") shirt_json.N("id",mod_shirt);
        shirt_json.L("lvl",1);
        jSONObject.N("shirt",shirt_json);
        this["a"](str, jSONObject);
    };

})
