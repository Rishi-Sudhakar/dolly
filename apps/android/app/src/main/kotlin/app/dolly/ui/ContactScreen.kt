package app.dolly.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import app.dolly.AppModel
import app.dolly.Fingerprint
import com.dolly.core.Contact
import com.dolly.core.Message
import com.dolly.core.toHex

@Composable
fun ContactScreen(model: AppModel, contact: Contact, onBack: () -> Unit, onConnect: () -> Unit) {
    BackHandler(onBack = onBack)
    var showDetails by remember { mutableStateOf(false) }
    val history by produceState(emptyList<Message>(), contact.identityKey.toHex()) { value = model.history(contact) }

    Column(Modifier.fillMaxSize().safeDrawingPadding()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("Back") }
            Text(contact.name, style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            TextButton(onClick = { showDetails = true }) { Text("Details") }
        }
        if (history.isEmpty()) {
            Box(Modifier.weight(1f).fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                Text("No messages yet.")
            }
        } else {
            MessageList(history, Modifier.weight(1f))
        }
        model.notice?.let {
            Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
        }
        Button(onClick = onConnect, modifier = Modifier.fillMaxWidth().padding(16.dp)) { Text("Connect") }
    }

    if (showDetails) Details(contact, onSave = model::update, onDismiss = { showDetails = false })
}

@Composable
private fun Details(contact: Contact, onSave: (Contact) -> Unit, onDismiss: () -> Unit) {
    var name by remember { mutableStateOf(contact.name) }
    var verified by remember { mutableStateOf(contact.verified) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Contact details") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true)
                Text(
                    Fingerprint.of(contact.identityKey),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.titleMedium,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("I compared this key with them in person or on a call", modifier = Modifier.weight(1f))
                    Switch(verified, { verified = it })
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onSave(Contact(contact.identityKey, name.trim().ifEmpty { contact.name }, verified, contact.addedAt))
                    onDismiss()
                },
            ) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
