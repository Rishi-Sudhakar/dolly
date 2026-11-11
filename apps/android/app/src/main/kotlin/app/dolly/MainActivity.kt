package app.dolly

import android.Manifest
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import app.dolly.ui.ContactScreen
import app.dolly.ui.ContactsScreen
import app.dolly.ui.SessionScreen
import com.dolly.core.Contact
import com.dolly.core.toHex

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val model = (application as DollyApplication).model
        setContent { DollyTheme { Root(model) } }
    }
}

@Composable
private fun DollyTheme(content: @Composable () -> Unit) {
    val context = LocalContext.current
    val colors = if (isSystemInDarkTheme()) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
    MaterialTheme(colorScheme = colors) {
        Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background, content = content)
    }
}

@Composable
private fun Root(model: AppModel) {
    var selected by rememberSaveable { mutableStateOf<String?>(null) }  // hex identity key of the open contact
    var starting by remember { mutableStateOf<Contact?>(null) }
    val permissions = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        // A session works without either permission (the notification only shows that it is running, and
        // the local-network one only matters for a peer on the same Wi-Fi), so go on whatever was answered.
        model.beginPairing(starting)
    }
    val startSession = { contact: Contact? ->
        starting = contact
        permissions.launch(arrayOf(Manifest.permission.POST_NOTIFICATIONS, "android.permission.ACCESS_LOCAL_NETWORK"))
    }

    val open = model.contacts.firstOrNull { it.identityKey.toHex() == selected }
    when {
        model.phase != AppModel.Phase.Idle -> SessionScreen(model)
        open != null -> ContactScreen(model, open, onBack = { selected = null }, onConnect = { startSession(open) })
        else -> ContactsScreen(model, onOpen = { selected = it.identityKey.toHex() }, onNew = { startSession(null) })
    }
}
