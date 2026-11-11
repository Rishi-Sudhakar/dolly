package app.dolly.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import app.dolly.AppModel
import com.dolly.core.Contact
import com.dolly.core.toHex

@Composable
fun ContactsScreen(model: AppModel, onOpen: (Contact) -> Unit, onNew: () -> Unit) {
    var showKey by remember { mutableStateOf(false) }

    Scaffold(
        floatingActionButton = { ExtendedFloatingActionButton(onClick = onNew) { Text("New conversation") } },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Row(
                Modifier.fillMaxWidth().padding(start = 16.dp, end = 8.dp, top = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Dolly", style = MaterialTheme.typography.headlineMedium, modifier = Modifier.weight(1f))
                TextButton(onClick = { showKey = true }) { Text("My key") }
            }
            model.notice?.let {
                Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
            }
            if (model.contacts.isEmpty()) {
                Box(Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
                    Text(
                        "No contacts yet. Start a conversation, swap links with someone, and they appear here.",
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            } else {
                LazyColumn(contentPadding = PaddingValues(bottom = 96.dp), verticalArrangement = Arrangement.Top) {
                    items(model.contacts, key = { it.identityKey.toHex() }) { contact ->
                        ListItem(
                            headlineContent = { Text(contact.name) },
                            supportingContent = { Text(if (contact.verified) "Verified" else "Not verified") },
                            colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                            modifier = Modifier.clickable { onOpen(contact) },
                        )
                    }
                }
            }
        }
    }

    if (showKey) {
        AlertDialog(
            onDismissRequest = { showKey = false },
            confirmButton = { TextButton(onClick = { showKey = false }) { Text("Close") } },
            title = { Text("Your key") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(model.myFingerprint, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
                    Text("Read this aloud to a contact, or have them read theirs, to be sure you are talking to the right person.")
                }
            },
        )
    }
}
