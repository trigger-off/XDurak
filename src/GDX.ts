export class Preferences{
    public instance: Java.Wrapper;
    constructor(instance: Java.Wrapper){
        this.instance = instance;
    }

    clear(){
        this.instance.clear();
    }

    contains(key: string): boolean{
        return this.instance.contains(key);
    }

    flush(): void{
        this.instance.flush();
    }

    getBoolean(key: string, defVal?: boolean): boolean{
        if (defVal !== undefined){
            return this.instance.getBoolean(key,defVal);
        }
        return this.instance.getBoolean(key);
    }

    getFloat(key: string, defVal?: number): number{
        if (defVal !== undefined){
            return this.instance.getFloat(key,defVal);
        }
        return this.instance.getFloat(key);
    }
    
    getInteger(key: string, defVal?: number): number{
        if (defVal !== undefined){
            return this.instance.getInteger(key,defVal);
        }
        return this.instance.getInteger(key);
    }

    getLong(key: string, defVal?: number): number{
        if (defVal !== undefined){
            return this.instance.getLong(key,defVal);
        }
        return this.instance.getLong(key);
    }

    getString(key: string, defVal?: string): string{
        if (defVal !== undefined){
            return this.instance.getString(key,defVal);
        }
        return this.instance.getString(key);
    }

    putBoolean(key: string, value: boolean): Java.Wrapper{
        return this.instance.putBoolean(key,value);
    }

    putFloat(key: string, value: number): Java.Wrapper{
        return this.instance.putFloat(key,value);
    }

    putInteger(key: string, value: number): Java.Wrapper{
        return this.instance.putInteger(key,value);
    }

    putLong(key: string, value: number): Java.Wrapper{
        return this.instance.putLong(key,value);
    }

    putString(key: string, value: string): Java.Wrapper{
        return this.instance.putString(key,value);
    }
    
    remove(key: string): void{
        this.instance.remove(key);
    }

}

