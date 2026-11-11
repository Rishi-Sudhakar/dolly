package app.dolly

import android.app.Application

class DollyApplication : Application() {
    val model by lazy { AppModel(this) }

    override fun onCreate() {
        super.onCreate()
        model.start()
    }
}
