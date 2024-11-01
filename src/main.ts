import XDurak from "./XDurak.js";
import {Durak} from "./RSTGAMES.js";

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
    public script_update: {old: number, new: number} = {old: 0, new: Number(XDurak.VERSION)};
    constructor(startActivity: Java.Wrapper){
        this.preferences = new Preferences(startActivity.getPreferences("XDurak"));
        this.script_update.old = Number(this.preferences.getString("version","0"));
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
                    mpf = new ModPreferences(instance);
                    return 'stop'

                }
            }
        })
    } catch {}


    const JGdx = Durak.JGdx;
    const StartActivity = Durak.StartActivity;
    const auth_cancel_handler = Durak.auth_cancel_handler;
    const GameController = Durak.GameController;
    const Game = Durak.Game;
    const JString = Durak.JString;
    const InputEvent = Durak.InputEvent;
    const JoinToGameClickListener = Durak.JoinToGameClickListener;
    const ListPublicGames = Durak.ListPublicGames;
    const Logger = Durak.Logger;
    const SearchController = Durak.SearchController;
    const MainScreenProfile = Durak.MainScreenProfile;
    const ClickListener = Durak.ClickListener;
    const Texture = Durak.Texture;
    const Image = Durak.Image;
    const MatchScreen = Durak.MatchScreen;
    const SearchFilter = Durak.SearchFilter;
    const g_packet_handler = Durak.g_packet_handler;
    const game_packet_handler = Durak.game_packet_handler;
    const JSONObject = Durak.JSONObject;
    const JSONArray = Durak.JSONArray;
    const DiscardClickListener = Durak.DiscardClickListener;
    const JsonIpServerConnector = Durak.JsonIpServerConnector;
    const features_handler = Durak.features_handler;
    const enemy_pickup_card_animate_l = Durak.enemy_pickup_card_animate_l;
    const enemy_pickup_card_animate_a = Durak.enemy_pickup_card_animate_a;
    const utils_4_cards = Durak.utils_4_cards;
    const end_turn_handler = Durak.end_turn_handler;
    const mode_handler = Durak.mode_handler;
    const drag_n_beat = Durak.drag_n_beat;
    const win_handler = Durak.win_handler;
    const Toast = Durak.Toast;
    const CARD_VIEW_TYPE = Durak.CARD_VIEW_TYPE;
    const ShopAssets = Durak.ShopAssets;
    const cheater_card_click_listener = Durak.cheater_card_click_listener;
    const RSTGamePlaceOnClick = Durak.RSTGamePlaceOnClick;
    const PLACE_TYPE = Durak.PLACE_TYPE;
    const btn_ready_on_handler = Durak.btn_ready_on_handler;
    const MainScreenAvatarClickListener = Durak.MainScreenAvatarClickListener;
    const game_reset_handler = Durak.game_reset_handler;
    const b_handler = Durak.b_handler;
    const tfs_handler = Durak.tfs_handler;
    const smile_handler = Durak.smile_handler;
    const RSTGamePlace = Durak.RSTGamePlace;
    const cp_handler = Durak.cp_handler;

    function show_menu(){
        Java.scheduleOnMainThread(() => {
            const startActivity = new Durak.startActivity(JGdx.app.value);
            const activityInstance = startActivity.instance;
            const gameController = new Durak.gameController(startActivity.applicationListener);
            const classname = gameController.screen.$className;
            if (classname == "com.rstgames.durak.screens.a") {
                const searchDialog = new DialogBuilder(activityInstance);
                const searchInput = new EditText(activityInstance,"","Нужная ставка");
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
                const connectToFirstGameDialog = new DialogBuilder(activityInstance);
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
                const matchScreen = new Durak.matchScreen(gameController.screen);
                const matchController = matchScreen.matchController;
                // const cardsController = new Durak.cardsController(matchScreen.cardsController);
                const ch = matchController.ch ?? false;

                const settingsDialogB = new DialogBuilder(activityInstance);
                const layout = new LinearLayout(activityInstance);
                const watch_cards_checkbox = new CheckBox(activityInstance,"Просмотр карт (Заменяет просмотр профиля)",mpf.watch_cards);
                const highlight_checkbox = new CheckBox(activityInstance, "Подсвечивать карты", mpf.highlight);
                const auto_category = new TextView(activityInstance,"Автоматизация: ");
                const auto_ready_checkbox = new CheckBox(activityInstance,"Автоматически подтверждать игру",mpf.auto_ready);
                const auto_done_checkbox = new CheckBox(activityInstance,"Автоматически заканчивать Пас/Готов, если нет карт",mpf.auto_done);
                const auto_take_checkbox = new CheckBox(activityInstance,"Автоматически подбирать карты, если нет карт", mpf.auto_take);
                const auto_beat_checkbox = new CheckBox(activityInstance,"Автоматически отбиваться, если есть карты", mpf.auto_beat);
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
                    const cheater_category = new TextView(activityInstance, "Шулер: ")
                    const toast_cheater_checkbox = new CheckBox(activityInstance, "Отображать сообщение о шулере",mpf.toast_cheater);
                    toast_cheater_checkbox.setCheckedChangeListener((b,isChecked) => {
                        mpf.toast_cheater = isChecked;
                    });
                    const grey_card_cheater_checkbox = new CheckBox(activityInstance, "Помечать серым нечестную карту",mpf.grey_card_cheater);
                    grey_card_cheater_checkbox.setCheckedChangeListener((b,isChecked) => {
                        mpf.grey_card_cheater = isChecked;
                    });
                    const autoclick_cheater_checkbox = new CheckBox(activityInstance, "Автоматически нажимать на нечестную карту",mpf.autoclick_cheater);
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
                const skinSettingsDialogB = new DialogBuilder(activityInstance);
                const layout = new LinearLayout(activityInstance); layout.setOrientation("VERTICAL");
                const desc = new TextView(activityInstance,"Введите id скина в правильном поле или оставьте пустым, чтобы не заменять.\nВсе изменения видны только вам.")
                const smile_editText = new EditText(activityInstance, mpf.smile, "smile_classic");
                const shirt_editText = new EditText(activityInstance, mpf.shirt, "shirt_classic");
                const frame_editText = new EditText(activityInstance, mpf.frame, "frame_classic");
                layout.addViews([desc,smile_editText,shirt_editText,frame_editText]);
                skinSettingsDialogB.setTitle("Скинченджер");
                skinSettingsDialogB.setView(layout);
                skinSettingsDialogB.setPositiveButton("OK",()=>{
                    const tcpServer = gameController.tcpServer;
                    const json = new Durak.jSONObject();
                    mpf.smile = smile_editText.getText();
                    mpf.shirt = shirt_editText.getText();
                    mpf.frame = frame_editText.getText();
                    json.put_object("v",mpf.frame);
                    json.put_object("k","frame");
                    tcpServer.recv("uu", json.instance)
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
    Durak.searchController.minBet.implementation = function () {
        const searchController = new Durak.searchController(this);
        let result = searchController.minBet();
        if (mpf.accurate_search > 0){result = mpf.accurate_search} // замена мин и макс ставки для точного поиска
        return result;
    };
    // функция для получения максимальной ставки
    Durak.searchController.maxBet.implementation = function () {
        const searchController = new Durak.searchController(this);
        let result = searchController.maxBet();
        if (mpf.accurate_search > 0){result = mpf.accurate_search} // замена мин и макс ставки для точного поиска
        return result;
    };

    function inject_mod_menu(this: Java.Wrapper) {
        this["show"]();
        const startActivity = new Durak.startActivity(JGdx.app.value);
        const files = JGdx.files.value;
        const graphics = JGdx.graphics.value;
        const gameController = new Durak.gameController(startActivity.applicationListener);
        const stageInstance = gameController.stage;

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
    
    Durak.startActivity.onCreate.implementation = function (this: Java.Wrapper,bundle: Java.Wrapper) {
        const startActivity = new Durak.startActivity(this);
        mpf = new ModPreferences(this);
        startActivity.onCreate(bundle);
        if (mpf.script_update.old < mpf.script_update.new) {
            Java.scheduleOnMainThread(() => {
                Toast.makeText(startActivity.instance,JString.$new(`XDurak Script: ${mpf.script_update.old} => ${mpf.script_update.new}`), Toast.LENGTH_SHORT.value).show();
            })
        }
    };
    Durak.startActivity.YesOrNoDialog.implementation = function (click_handler: Java.Wrapper, header: string, positive: string, negative: string, cancelable: boolean) {
        const startActivity = new Durak.startActivity(this);
        if (click_handler.$className == Durak.auth_cancel_handler.$className) {
            header = "Способ входа:";
            negative = "Токен";
            positive = "Гугл";
        }
        startActivity.YesOrNoDialog(click_handler, header, positive, negative, cancelable);
    };
    // Negative | Выйти | Токен
    Durak.startActivity.auth_cancel_handler.negative.implementation = function (this: Java.Wrapper) {
        const startActivity = new Durak.startActivity(this);
        const dialog = new DialogBuilder(startActivity.instance);
        const edittext = new EditText(startActivity.instance);
        const gameController = startActivity.gameController;
        edittext.setHint("Токен");
        dialog.setTitle("Введите токен");
        dialog.setView(edittext);
        dialog.setPositiveButton("ОК", (dialog,which) => {
            const token = edittext.getText();
            startActivity.set_token(token); // сохранение токена в shared preferences
            if (gameController != null) {
                const tcpServer = gameController.tcpServer;
                if (tcpServer.instance != null || tcpServer.instance != undefined) {
                    tcpServer.token = token; // сохранение токена в нынешней сессии
                    tcpServer.auth(false); // авторизация
                }
            }
        })
        dialog.show();
    };

    Logger["info"].overload('java.lang.String').implementation = function (str: string) {
        console.log(str);
             
        this["info"](str);
    };



    Durak.clickListener.get_clicked(MainScreenAvatarClickListener).implementation = function (inputEvent: Java.Wrapper, f: number, f2: number) {
        const clickListener = new Durak.clickListener(this);
        clickListener.clicked(inputEvent, f, f2);
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
    Durak.searchFilter.show.implementation = inject_mod_menu;
    Durak.listPublicGames.show.implementation = inject_mod_menu;
    Durak.matchScreen.show.implementation = inject_mod_menu;
    Durak.shopAssets.show.implementation = inject_mod_menu;
    
    // обработка пакета "g"
    Durak.packetHandler.get_packet_received(g_packet_handler).implementation = function (this:Java.Wrapper, str: string, jSONObject: Java.Wrapper) {
        Durak.packetHandler.get_packet_received(g_packet_handler).call(this, str, jSONObject);
        if (mpf.connect_to_first_game) {
            const clickListener = JoinToGameClickListener.$new(this,jSONObject);
            Durak.clickListener.get_clicked(clickListener)(InputEvent.$new(),0,0);
            mpf.connect_to_first_game = false;
        }
        
    };

    // получение данных о матче
    Durak.packetHandler.get_packet_received(game_packet_handler).implementation = function (str: string, jSONObject: Java.Wrapper) {
        const packetHandler = new Durak.packetHandler(this);
        const json = new Durak.jSONObject(jSONObject);
        matchData = new MatchData(json.opt_int("id"));
        packetHandler.packet_received(str, jSONObject);

    };

    Durak.packetHandler.get_packet_received(game_reset_handler).implementation = function (str: string, jSONObject: Java.Wrapper) {
        const packetHandler = new Durak.packetHandler(this);
        matchData = new MatchData(matchData.id);
        packetHandler.packet_received(str, jSONObject);
    };

    Durak.clickListener.get_clicked(DiscardClickListener).implementation = function (inputEvent: Java.Wrapper, f: number, f2: number) {
        const clickListener = new Durak.clickListener(this);
        clickListener.clicked(inputEvent, f, f2);
        if (clickListener.outerInstance.instance.$className == Durak.MatchScreen.$className) {
            const matchScreen = new Durak.matchScreen(clickListener.outerInstance.instance);
            const net_instance = matchScreen.gameController.tcpServer; // TCPServer
            const discard_json = new Durak.jSONObject();
            const discard_array = new Durak.jSONArray();
            matchData.discard_cards.forEach((e) => {
                discard_array.push(e); // .push
            });
            discard_json.put_object("c",discard_array);
            net_instance.recv("discard",discard_json.instance);
        }

    };

    Durak.jsonIpServerConnector.sendOnlyStr.implementation = function (str: string) {
        const tcpServer = new Durak.jsonIpServerConnector(this);
        if (str === "show_discard") {
            // блокировка отправки пакета на покупку отображения битых карт
            return
        }
        tcpServer.sendOnlyStr(str);
    };

    //обработка пакета "features"
    Durak.packetHandler.get_packet_received(features_handler).implementation = function (str: string, jSONObject: Java.Wrapper) {
        // редактирование цен на 0
        const json = new Durak.jSONObject(jSONObject);
        const packetHandler = new Durak.packetHandler(this);
        json.put_int("dis",0);
        json.put_int("hl",0);
        packetHandler.packet_received(str, jSONObject);
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
    b_handler["a"].implementation = enemy_drop_card_handler;
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
        // aka get_tcpServer
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
        const utils4cards = matchController.G.value;
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
    drag_n_beat["a"].implementation = function (i: number) {
        this["a"](i);
    };
    // анимация и отправка пакета "t"
    drag_n_beat["b"].implementation = function (i: number) {
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

    cheater_card_click_listener["$init"].implementation = function (w, i, str) {
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
            known_cards.setMessage(matchData.enemy_hand_cards.length == 0 ? "Известные карты:\n" + formatSortedCards(sortCards(matchData.enemy_known_cards[place_id],getSuit(trump))) + "\nНеизвестные карты:\n" + formatSortedCards(sortCards(unknown_cards,getSuit(trump)))  : formatSortedCards(sortCards(matchData.enemy_hand_cards,getSuit(trump))));
            known_cards.show();
        });
    };
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

    smile_handler["a"].implementation = function (str: string, jSONObject: Java.Wrapper) {
        const mod_smile = mpf.smile;
        const place_id = jSONObject.B("p");
        const matchScreen = this._a.value;
        const matchController = matchScreen._w.value;
        if (place_id == matchController.z.value && mod_smile != "") jSONObject.N("a",mod_smile); 
        this["a"](str, jSONObject);
    };

    MainScreenProfile["n"].implementation = function (frame_id: string) {
        console.log(`b0.n is called: str=${frame_id}`);

        const mod_frame = mpf.frame;
        if (mod_frame != "") frame_id = mod_frame;
        this["n"](frame_id);
    };
    RSTGamePlace["h"].implementation = function (str: string, str2: string, frame_id: string, str4: string, player_id: number, j2: number, i: number, z: boolean, group: Java.Wrapper, image: Java.Wrapper) {
        const mod_frame = mpf.frame;
        const gameController = this._a.value;
        const tcpServer = gameController._d.value;
        const my_player_id = tcpServer.c0.value; 
        if (player_id.valueOf() == my_player_id.valueOf() && mod_frame != "") frame_id = mod_frame
        this["h"](str, str2, frame_id, str4, player_id, j2, i, z, group, image);
    };
    cp_handler["a"].implementation = function (str: string, jSONObject: Java.Wrapper) {
        const mod_shirt = mpf.shirt
        const shirt_json = jSONObject.E("shirt");
        if (mod_shirt != "") shirt_json.N("id",mod_shirt);
        shirt_json.L("lvl",1);
        jSONObject.N("shirt",shirt_json);
        this["a"](str, jSONObject);
    };

})
