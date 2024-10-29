const JString = Java.use('java.lang.String');
const Html = Java.use('android.text.Html');

type HeightAndWidth  = number | 'MATCH_PARENT' | 'FILL_PARENT' | 'WRAP_CONTENT'

// const
function initCounter(start = 0) {
    let counter = start;
    return () => counter++;
}

const lambdaCounter = initCounter();

export class Color {
    static Color = Java.use('android.graphics.Color');

    static parseColor(color: string): number {

        return this.Color.parseColor(color);
    }
}

export abstract class View {
    public element: Java.Wrapper;
    static jClass: Java.Wrapper = Java.use('android.view.View');

    constructor(instance: Java.Wrapper) {
        this.element = this.createElement(instance);
    }

    // Абстрактный метод, который должны реализовать подклассы
    protected abstract createElement(instance: Java.Wrapper): Java.Wrapper;

    private View$OnClickListener(fn: (view: Java.Wrapper) => void): Java.Wrapper {
        return Java.registerClass({
            name: `com.tr1gger0ff.OnClickListener$${lambdaCounter()}`,
            implements: [Java.use('android.view.View$OnClickListener')],
            methods: {onClick: fn},
        }).$new();
    }

    private View$OnLongClickListener(fn: (view: Java.Wrapper) => void): Java.Wrapper {
        return Java.registerClass({
            name: `com.tr1gger0ff.OnLongClickListener$${lambdaCounter()}`,
            implements: [Java.use('android.view.View$OnLongClickListener')],
            methods: {
                onLongClick: function (view: Java.Wrapper): boolean {
                    fn(view);
                    return true;
                },
            },
        }).$new();
    }

    private View$OnTouchListener(fn: (view: Java.Wrapper, motionEvent: Java.Wrapper) => void): Java.Wrapper {
        return Java.registerClass({
            name: `com.tr1gger0ff.OnTouchListener$${lambdaCounter()}`,
            implements: [Java.use('android.view.View$OnTouchListener')],
            methods: {
                onTouch(view: Java.Wrapper, motionEvent: Java.Wrapper): boolean {
                    fn(view, motionEvent);
                    return true;
                },
            },
        }).$new();
    }

    setClickListener(callback: (view: Java.Wrapper) => void, replace: boolean): void {
        if (replace) {
            this.element.setOnClickListener(this.View$OnClickListener(callback))
        } else {
            this.element.addEventListener(this.View$OnClickListener(callback))
        }
    }

    setLongClickListener(callback: (view: Java.Wrapper) => void, replace: boolean): void {
        if (replace) {
            this.element.setOnLongClickListener(this.View$OnLongClickListener(callback))
        } else {
            this.element.addEventListener(this.View$OnLongClickListener(callback))
        }
    }

    setTouchListener(callback: (view: Java.Wrapper, motionEvent: Java.Wrapper) => void, replace: boolean): void {
        if (replace) {
            this.element.setOnTouchListener(this.View$OnTouchListener(callback))
        } else {
            this.element.addEventListener(this.View$OnTouchListener(callback))
        }
    }

    setEnabled(state: boolean): void {
        this.element.setEnabled(state);
    }

    setVisibility(visibility: 'VISIBLE' | 'INVISIBLE' | 'GONE'): void {
        this.element.setVisibility(View.jClass[visibility].value);
    }

    setBackgroundColor(color: number | string): void {
        if (typeof color === 'string') {
            color = Color.parseColor(color);
        }
        this.element.setBackgroundColor(color);
    }

    setLayoutParams(layoutParams: LayoutParams | Java.Wrapper) {
        if (layoutParams instanceof LayoutParams) {
            this.element.setLayoutParams(layoutParams.element)
        } else {
            this.element.setLayoutParams(layoutParams)
        }
    }

    getLayoutParams(): LayoutParams {
        return new LayoutParams(Java.cast(this.element.getLayoutParams(),LayoutParams.jClass));
    }

}

export class TextView extends View {
    static jClass = Java.use('android.widget.TextView');

    protected createElement(instance: Java.Wrapper): Java.Wrapper {
        return TextView.jClass.$new(instance);
    }

    constructor(instance: Java.Wrapper, text?: string) {
        super(instance);
        if (text) {
            this.setText(text);
        }
    }

    getText(): string {
        return Java.cast(this.element.getText(), Java.use("java.lang.CharSequence")).toString()
    }

    getTextSize(): number {
        return this.element.getTextSize();
    }

    setText(text: string): void {
        this.element.setText(JString.$new(text))
    }

    setHint(text: string): void {
        this.element.setHint(JString.$new(text))
    }

    setTextSize(size: number): void {
        this.element.setTextSize(size);
    }

    setTextColor(color: number | string): void {
        if (typeof color === 'string') {
            color = Color.parseColor(color);
        }
        this.element.setTextColor(color);
    }

}

export class EditText extends TextView {
    private BufferType: Java.Wrapper = Java.use("android.widget.TextView$BufferType")
    static jClass = Java.use('android.widget.EditText');

    protected createElement(instance: Java.Wrapper): Java.Wrapper {
        return EditText.jClass.$new(instance);
    }

    constructor(instance: Java.Wrapper, text?: string, hint?: string) {
        super(instance);
        if (hint) {
            this.setHint(hint)
        }
        if (text) {
            this.setText(text,"NORMAL")
        }
    }

    setText(text: string, bufferType: "EDITABLE" | "NORMAL" | "SPANNABLE" = "EDITABLE"): void {
        this.element.setText(JString.$new(text), this.BufferType[bufferType].value)
    }
}

export class LinearLayout extends View {
    private LinearLayout: Java.Wrapper = Java.use('android.widget.LinearLayout');
    static jClass = Java.use('android.widget.LinearLayout');

    protected createElement(instance: Java.Wrapper): Java.Wrapper {
        return LinearLayout.jClass.$new(instance);
    }

    setOrientation(orientation: "HORIZONTAL" | "VERTICAL"): void {
        this.element.setOrientation(this.LinearLayout[orientation].value);
    }

    addView(view: View | Java.Wrapper): void {
        if (view instanceof View) {
            this.element.addView(view.element)
        } else {
            this.element.addView(view)
        }
    }

    addViews(views: Array<View | Java.Wrapper>): void {
        views.forEach(view => {
            this.addView(view);
        })
    }
}

export class CheckBox extends TextView {
    static jClass = Java.use('android.widget.CheckBox');

    private CompoundButton$OnCheckedChangeListener(
        fn: (buttonView: Java.Wrapper, isChecked: boolean) => void,
    ): Java.Wrapper {
        return Java.registerClass({
            name: `com.tr1gger0ff_OnCheckedChangeListener$${lambdaCounter()}`,
            implements: [Java.use('android.widget.CompoundButton$OnCheckedChangeListener')],
            methods: {onCheckedChanged: fn},
        }).$new();
    }

    protected createElement(instance: Java.Wrapper): Java.Wrapper {
        return CheckBox.jClass.$new(instance);
    }

    constructor(instance: Java.Wrapper, text?: string, isChecked?: boolean) {
        super(instance, text);
        if (isChecked) this.setChecked(isChecked);
    }

    setCheckedChangeListener(callback: (buttonView: Java.Wrapper, isChecked: boolean) => void): void {
        this.element.setOnCheckedChangeListener(this.CompoundButton$OnCheckedChangeListener(callback));
    }

    isChecked(): boolean {
        return this.element.isChecked();
    }

    setChecked(state: boolean): void {
        this.element.setChecked(state);
    }
}

export class Dialog {
    public element: Java.Wrapper;
    static jClass = Java.use('android.app.Dialog');

    constructor(dialog: Java.Wrapper) {
        this.element = dialog;
    }

    dismiss(): void {
        this.element.dismiss();
    }

    cancel(): void {
        this.element.cancel();
    }

    hide(): void {
        this.element.hide();
    }

    setCancelable(state: boolean) {
        this.element.setCancelable(state);
    }

    setTitle(title: string): void {
        this.element.setTitle(JString.$new(title));
    }

    isShowing(): boolean {
        return this.element.isShowing();
    }

    show(): void {
        this.element.show();
    }

}

export class AlertDialog extends Dialog {
    private DialogInterface$OnClickListener(fn: (dialog: Java.Wrapper, which: number) => void): Java.Wrapper {
        return Java.registerClass({
            name: `com.tr1gger0ff_OnClickListener$${lambdaCounter()}`,
            implements: [Java.use('android.content.DialogInterface$OnClickListener')],
            methods: {onClick: fn},
        }).$new();
    }

    setButton(which: 'BUTTON_POSITIVE' | 'BUTTON_NEUTRAL' | 'BUTTON_NEGATIVE', text: string, callback: (dialog: Java.Wrapper, which: number) => void): void {
        this.element.setButton(Dialog.jClass[which].value, JString.$new(text), this.DialogInterface$OnClickListener(callback));
    }

    setMessage(text: string): void {
        this.element.setMessage(JString.$new(text));
    }

    setView(view: View | Java.Wrapper): void {
        if (view instanceof View) {
            this.element.setView(view.element);
        } else {
            this.element.setView(view);
        }
    }

}

export class DialogBuilder {
    static jClass = Java.use('android.app.AlertDialog$Builder');

    private DialogInterface$OnClickListener(fn: (dialog: Java.Wrapper, which: number) => void): Java.Wrapper {
        return Java.registerClass({
            name: `com.tr1gger0ff_OnClickListener$${lambdaCounter()}`,
            implements: [Java.use('android.content.DialogInterface$OnClickListener')],
            methods: {onClick: fn},
        }).$new();
    }

    private DialogInterface$OnCancelListener(fn: (dialog: Java.Wrapper) => void): Java.Wrapper {
        return Java.registerClass({
            name: `com.tr1gger0ff_OnCancelListener$${lambdaCounter()}`,
            implements: [Java.use('android.content.DialogInterface$OnCancelListener')],
            methods: {onCancel: fn},
        }).$new();
    }

    private DialogInterface$OnDismissListener(fn: (dialog: Java.Wrapper) => void): Java.Wrapper {
        return Java.registerClass({
            name: `com.tr1gger0ff_OnDismissListener$${lambdaCounter()}`,
            implements: [Java.use('android.content.DialogInterface$OnDismissListener')],
            methods: {onDismiss: fn},
        }).$new();
    }

    public dialogInstance: Java.Wrapper;

    constructor(instance: Java.Wrapper) {
        this.dialogInstance = DialogBuilder.jClass.$new(instance);
    }

    setTitle(title: string): void {
        this.dialogInstance.setTitle(JString.$new(title));
    }

    setMessage(message: string): void {
        this.dialogInstance.setMessage(JString.$new(message));
    }

    setCancelable(state: boolean) {
        this.dialogInstance.setCancelable(state);
    }

    setPositiveButton(text: string, callback: (dialog: Java.Wrapper, which: number) => void): void {
        this.dialogInstance.setPositiveButton(JString.$new(text), this.DialogInterface$OnClickListener(callback));
    }

    setNegativeButton(text: string, callback: (dialog: Java.Wrapper, which: number) => void): void {
        this.dialogInstance.setNegativeButton(JString.$new(text), this.DialogInterface$OnClickListener(callback));
    }

    setNeutralButton(text: string, callback: (dialog: Java.Wrapper, which: number) => void): void {
        this.dialogInstance.setNeutralButton(JString.$new(text), this.DialogInterface$OnClickListener(callback));
    }

    setCancelListener(callback: (dialog: Java.Wrapper) => void) {
        this.dialogInstance.setOnCancelListener(this.DialogInterface$OnCancelListener(callback));
    }

    setDismissListener(callback: (dialog: Java.Wrapper) => void) {
        this.dialogInstance.setOnDismissListener(this.DialogInterface$OnDismissListener(callback));
    }

    setView(view: View | Java.Wrapper): void {
        if (view instanceof View) {
            this.dialogInstance.setView(view.element);
        } else {
            this.dialogInstance.setView(view);
        }
    }

    show(): AlertDialog {
        let alertDialog = this.dialogInstance.show();
        alertDialog = Java.cast(alertDialog, AlertDialog.jClass)
        return new AlertDialog(alertDialog);
    }

    create(): AlertDialog {
        let alertDialog = this.dialogInstance.create();
        alertDialog = Java.cast(alertDialog, AlertDialog.jClass)
        return new AlertDialog(alertDialog);
    }

}

export class SharedPreferencesEditor {
    static jClass = Java.use('android.content.SharedPreferences$Editor');
    public element: Java.Wrapper;

    constructor(spfEditor: Java.Wrapper) {
        this.element = spfEditor;
    }

    apply(): void {
        this.element.apply();
    }

    clear(): void {
        this.element.clear();
    }

    commit(): boolean {
        return this.element.commit();
    }

    putBoolean(key: string, value: boolean): void {
        this.element.putBoolean(key,value);
    }

    putFloat(key: string, value: number): void {
        this.element.putFloat(key,value);
    }

    putInt(key: string, value: number): void {
        this.element.putInt(key,value | 0);
    }

    putLong(key: string, value: number): void {
        this.element.putLong(key,value);
    }

    putString(key: string, value: string): void {
        this.element.putString(key,value);
    }

    remove(key: string): void {
        this.element.remove(key);
    }

}

export class SharedPreferences {
    static jClass = Java.use("android.content.SharedPreferences");
    public element: Java.Wrapper;

    constructor(spf: Java.Wrapper) {
        this.element = spf;
    }

    contains(key: string): boolean {
        return this.element.contains(key);
    }

    edit(): SharedPreferencesEditor {
        return new SharedPreferencesEditor(this.element.edit());
    }

    getBoolean(key: string, defValue: boolean): boolean {
        return this.element.getBoolean(key, defValue);
    }

    getFloat(key: string, defValue: number): number {
        return this.element.getFloat(key, defValue);
    }

    getInt(key: string, defValue: number): number {
        return this.element.getInt(key, defValue | 0);
    }

    getLong(key: string, defValue: number): number {
        return this.element.getLong(key, defValue);
    }

    getString(key: string, defValue: string): string {
        return this.element.getString(key, defValue);
    }

}

export class LayoutParams {
    static jClass = Java.use('android.view.ViewGroup$LayoutParams');
    element: Java.Wrapper;

    constructor(element?: Java.Wrapper) {
        if (element){
            this.element = element;            
        } else {
            this.element = LayoutParams.jClass.$new();
        }
    }

    set width (width: HeightAndWidth) {
        if (typeof width === 'string') {
            this.element.width.value = LayoutParams.jClass[width].value;
            return
        }
        this.element.width.value = width;
    }

    set height (height: HeightAndWidth) {
        if (typeof height === 'string') {
            this.element.height.value = LayoutParams.jClass[height].value;
            return
        }
        this.element.height.value = height;
    }

}


