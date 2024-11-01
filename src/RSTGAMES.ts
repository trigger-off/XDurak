import XDurak from "./XDurak.js";

class XClass {
    constructor(public instance: Java.Wrapper) {
        this.instance = instance;
    }
}

class GameController extends XClass {
    get matchScreen(): MatchScreen {
        return new MatchScreen(this.instance._N.value);
    }

    get tcpServer(): TcpServer {
        return new TcpServer(this.instance.a.value);
    }

    get stage(): Java.Wrapper {
        return this.instance.a0.value;
    }

    get screen(): Java.Wrapper {
        return this.instance.getScreen();
    }
}

class AuthCancelHandler {
    constructor(public instance: Java.Wrapper) {
        this.instance = instance;
    }

    positive(): void {
        this.instance.a();
    }

    negative(): void {
        this.instance.b();
    }

    static get positive(): Java.Method {
        return Durak.auth_cancel_handler.a;
    }

    static get negative(): Java.Method {
        return Durak.auth_cancel_handler.b;
    }
}

class StartActivity extends XClass {
    onCreate(bundle: Java.Wrapper) {
        this.instance.onCreate(bundle);
    }

    YesOrNoDialog(click_handler: Java.Wrapper, header: string, positive: string, negative: string, cancelable: boolean) {
        this.instance.p(click_handler, header, positive, negative, cancelable);
    }

    set_token(token: string) {
        this.instance.A(token);
    }
    get applicationListener(): Java.Wrapper {
        return this.instance.getApplicationListener();
    }

    get gameController(): GameController {
        return new GameController(this.instance._a.value);
    }

    static get onCreate(): Java.Method {
        return Durak.StartActivity.onCreate;
    }

    static get YesOrNoDialog(): Java.Method {
        return Durak.StartActivity.instance.p;
    }

    static auth_cancel_handler = AuthCancelHandler;
}

class MatchScreen extends XClass {
    get gameController(): GameController {
        return new GameController(this.instance._a.value);
    }

    get matchController(): MatchController {
        return new MatchController(this.instance._w.value);
    }

    get cardsController(): CardsController {
        return new CardsController(this.instance._x.value);
    }

    get allCards(): Java.Wrapper[] {
        return this.instance._W.value;
    }

    static get update(): Java.Method {
        return Durak.MatchScreen.Q;
    }

    static get load_smiles_menu(): Java.Method {
        return Durak.MatchScreen.V;
    }

    static get show(): Java.Method {
        return Durak.MatchScreen.show;
    }
}

class MatchController extends XClass {
    get ch(): boolean {
        return this.instance.j.value;
    }

    get sw(): boolean {
        return this.instance.k.value;
    }

    get myPlaceId(): number {
        return this.instance.z.value;
    }

    get playersModeList(): number[] {
        return this.instance.p.value;
    }

    get cardUtils(): Utils4Cards {
        return new Utils4Cards(this.instance.G.value);
    }
}

class CardsController extends XClass {
    get trump(): string {
        return this.instance._i.value;
    }

    get discardCards(): string[] {
        return this.instance.o.value;
    }

    get playersCardsCount(): number[] {
        return this.instance._g.value;
    }
}

class PacketHandler extends XClass {
    get outerInstance(): XClass {
        return new XClass(this.instance._a.value);
    }

    static get_packet_received(jClass: Java.Wrapper): Java.Method {
        return jClass.a;
    }

    packet_received(key: string, jSONObject: Java.Wrapper): void {
        this.instance.a(key, jSONObject);
    }
}

class SearchController extends XClass {
    minBet(): number {
        return this.instance.b();
    }

    maxBet(): number {
        return this.instance.e();
    }

    static get minBet(): Java.Method {
        return Durak.SearchController.b;
    }

    static get maxBet(): Java.Method {
        return Durak.SearchController.e;
    }
}

class MainScreenProfile extends XClass {
    static get draw_avatar(): Java.Method {
        return Durak.MainScreenProfile.n;
    }
}

class ListPublicGames extends XClass {
    static get show(): Java.Method {
        return Durak.ListPublicGames.show;
    }
}

class SearchFilter extends XClass {
    static get show(): Java.Method {
        return Durak.SearchFilter.show;
    }
}

class JSONObject extends XClass {
    constructor(public instance: Java.Wrapper = Durak.JSONObject.$new()) {
        super(instance);
    }

    get_int(key: string): number {
        return this.instance.g(key);
    }

    opt_int(key: string): number {
        return this.instance.B(key);
    }

    put_int(key: string, value: number): void {
        this.instance.L(key, value);
    }

    opt_string(key: string): string {
        return this.instance.H(key);
    }

    put_object(key: string, value: any): void {
        this.instance.N(key, value);
    }

    opt_JSONObject(key: string): JSONObject {
        return new JSONObject(this.instance.E(key));
    }
}

class JSONArray extends XClass {
    constructor(public instance: Java.Wrapper = Durak.JSONArray.$new()) {
        super(instance);
    }

    push(value: any): void {
        this.instance.x(value);
    }
}

class ClickListener extends XClass {
    clicked(inputEvent: Java.Wrapper, f: number, f2: number): void {
        this.instance.clicked(inputEvent, f, f2);
    }

    get outerInstance(): XClass {
        return new XClass(this.instance.a.value);
    }

    static get_clicked(jClass: Java.Wrapper): Java.Method {
        return jClass.clicked;
    }
}

class JsonIpServerConnector extends XClass {
    static get sendOnlyStr(): Java.Method {
        return Durak.JsonIpServerConnector.o;
    }
    sendOnlyStr(key: string) {
        this.instance.o(key);
    }
}

class Utils4Cards extends XClass {
    static get draw_bito_card(): Java.Method {
        return Durak.utils_4_cards.g;
    }
}

class DragNBeat extends XClass {
    static get send_card(): Java.Method {
        return Durak.drag_n_beat.b;
    }
}

class CardViewType extends XClass {
    static get_card_view_type(viewType: "BACKGROUND" | "SIMPLE" | "GREY"): any {
        let view_type: string;
        switch (viewType) {
            case "BACKGROUND":
                view_type = "a"
                break
            case "SIMPLE":
                view_type = "b"
                break
            case "GREY":
                view_type = "c"
                break
            default:
                view_type = "b"
        }
        return Durak.CARD_VIEW_TYPE[view_type].value;
    }
}

class ShopAssets extends XClass {
    show() {
        this.instance.show();
    }

    static get show(): Java.Method {
        return Durak.ShopAssets.show;
    }
}

class TcpServer extends XClass {
    auth(googleAuth: boolean){
        this.instance.u(googleAuth);
    }

    send(key: string, jSONObject: Java.Wrapper): void {
        this.instance.p(key, jSONObject);
    }

    recv(key: string, jSONObject: Java.Wrapper): void {
        this.instance.h(key, jSONObject);
    }

    set token(token: string) {
        this.instance._w.value = token;
    }
}

export class Durak extends XDurak {
    static get JGdx() {
        return Java.use('com.badlogic.gdx.Gdx');
    }

    static get StartActivity() {
        return Java.use("com.rstgames.durak.StartActivity");
    }

    static get auth_cancel_handler() {
        return Java.use("com.rstgames.durak.StartActivity$b");
    }

    static get GameController() {
        return Java.use("com.rstgames.b");
    }

    static get Game() {
        return Java.use("com.badlogic.gdx.Game");
    }

    static get JString() {
        return Java.use("java.lang.String");
    }

    static get InputEvent() {
        return Java.use("com.badlogic.gdx.scenes.scene2d.InputEvent");
    }

    static get JoinToGameClickListener() {
        return Java.use("com.rstgames.durak.screens.c$e$a");
    }

    static get ListPublicGames() {
        return Java.use("com.rstgames.durak.screens.c");
    }

    static get Logger() {
        return Java.use("com.badlogic.gdx.utils.Logger");
    }

    static get SearchController() {
        return Java.use("com.rstgames.durak.controllers.a");
    }

    static get MainScreenProfile() {
        return Java.use("com.rstgames.utils.b0");
    }

    static get ClickListener() {
        return Java.use("com.badlogic.gdx.scenes.scene2d.utils.ClickListener");
    }

    static get Texture() {
        return Java.use("com.badlogic.gdx.graphics.Texture");
    }

    static get Image() {
        return Java.use("com.badlogic.gdx.scenes.scene2d.ui.Image");
    }

    static get MatchScreen() {
        return Java.use("com.rstgames.durak.screens.b");
    }

    static get SearchFilter() {
        return Java.use("com.rstgames.durak.screens.a");
    }

    static get g_packet_handler() {
        return Java.use("com.rstgames.durak.screens.c$e");
    }

    static get game_packet_handler() {
        return Java.use("com.rstgames.durak.screens.b$i");
    }

    static get JSONObject() {
        return Java.use("org.json.b");
    }

    static get JSONArray() {
        return Java.use("org.json.a");
    }

    static get DiscardClickListener() {
        return Java.use("com.rstgames.durak.utils.a$c");
    }

    static get JsonIpServerConnector() {
        return Java.use("com.rstgames.net.JsonIpServerConnector");
    }

    static get features_handler() {
        return Java.use("com.rstgames.durak.screens.b$j");
    }

    static get enemy_pickup_card_animate_l() {
        return Java.use("com.rstgames.durak.screens.b$o0$l");
    }

    static get enemy_pickup_card_animate_a() {
        return Java.use("com.rstgames.durak.screens.b$o0$a");
    }

    static get utils_4_cards() {
        return Java.use("com.rstgames.durak.utils.d");
    }

    static get end_turn_handler() {
        return Java.use("com.rstgames.durak.screens.b$o0");
    }

    static get mode_handler() {
        return Java.use("com.rstgames.durak.screens.b$m0");
    }

    static get drag_n_beat() {
        return Java.use("com.rstgames.durak.screens.b$j0");
    }

    static get win_handler() {
        return Java.use("com.rstgames.durak.screens.b$g1");
    }

    static get Toast() {
        return Java.use("android.widget.Toast");
    }

    static get CARD_VIEW_TYPE() {
        return Java.use("com.rstgames.durak.utils.Card$CARD_VIEW_TYPE");
    }

    static get ShopAssets() {
        return Java.use("com.rstgames.uiscreens.d");
    }

    static get cheater_card_click_listener() {
        return Java.use("com.rstgames.durak.screens.b$k0");
    }

    static get RSTGamePlaceOnClick() {
        return Java.use("com.rstgames.durak.utils.RSTGamePlace$a");
    }

    static get PLACE_TYPE() {
        return Java.use("com.rstgames.durak.utils.RSTGamePlace$PLACE_TYPE");
    }

    static get btn_ready_on_handler() {
        return Java.use("com.rstgames.durak.screens.b$y");
    }

    static get MainScreenAvatarClickListener() {
        return Java.use("com.rstgames.utils.b0$a");
    }

    static get game_reset_handler() {
        return Java.use("com.rstgames.durak.screens.b$i1");
    }

    static get b_handler() {
        return Java.use("com.rstgames.durak.screens.b$s0");
    }

    static get tfs_handler() {
        return Java.use("com.rstgames.durak.screens.b$p0");
    }

    static get smile_handler() {
        return Java.use("com.rstgames.durak.screens.b$r");
    }

    static get RSTGamePlace() {
        return Java.use("com.rstgames.durak.utils.RSTGamePlace");
    }

    static get cp_handler() {
        return Java.use("com.rstgames.durak.screens.b$l");
    }

    static gameController = GameController;
    static startActivity = StartActivity;
    static matchScreen = MatchScreen;
    static matchController = MatchController;
    static cardsController = CardsController;
    static packetHandler = PacketHandler;
    static searchController = SearchController;
    static mainScreenProfile = MainScreenProfile;
    static listPublicGames = ListPublicGames;
    static searchFilter = SearchFilter;
    static jSONObject = JSONObject;
    static jSONArray = JSONArray;
    static clickListener = ClickListener;
    static jsonIpServerConnector = JsonIpServerConnector;
    static utils4Cards = Utils4Cards;
    static dragNBeat = DragNBeat;
    static cardViewType = CardViewType;
    static shopAssets = ShopAssets;
    static tcpServer = TcpServer;
}