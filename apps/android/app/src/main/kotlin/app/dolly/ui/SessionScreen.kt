package app.dolly.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.dolly.AppModel
import app.dolly.AppModel.Phase

@Composable
fun SessionScreen(model: AppModel) {
    BackHandler(onBack = model::endSession)
    Column(Modifier.fillMaxSize().safeDrawingPadding()) {
        when (val phase = model.phase) {
            Phase.Idle -> Unit
            Phase.Preparing -> Waiting("Finding your address…", model)
            Phase.Ready, Phase.Connecting -> Pairing(model, connecting = phase == Phase.Connecting)
            Phase.Connected -> Chat(model)
            is Phase.Ended -> Ended(phase.reason, model)
        }
    }
}

@Composable
private fun Waiting(text: String, model: AppModel) {
    Column(
        Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator()
        Text(text)
        TextButton(onClick = model::endSession) { Text("Cancel") }
    }
}

@Composable
private fun Ended(reason: String, model: AppModel) {
    Column(
        Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(reason)
        Button(onClick = model::endSession) { Text("Done") }
    }
}

@Composable
private fun Pairing(model: AppModel, connecting: Boolean) {
    val context = LocalContext.current
    var pasted by rememberSaveable { mutableStateOf("") }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            model.expecting?.let { "Connect with ${it.name}" } ?: "New conversation",
            style = MaterialTheme.typography.headlineSmall,
        )
        model.networkWarning?.let { Text(it, color = MaterialTheme.colorScheme.error) }

        Text("Your key", style = MaterialTheme.typography.labelLarge)
        Text(model.myFingerprint, fontFamily = FontFamily.Monospace)

        Text("1. Send your link to your contact", style = MaterialTheme.typography.labelLarge)
        SelectionContainer {
            Text(model.myTicket, maxLines = 3, overflow = TextOverflow.Ellipsis, fontFamily = FontFamily.Monospace)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { context.copy(model.myTicket) }) { Text("Copy") }
            OutlinedButton(onClick = { context.share(model.myTicket) }) { Text("Share") }
        }

        if (connecting) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.padding(4.dp))
                Column {
                    Text("Connecting…")
                    Text("Their key: ${model.peerFingerprint}", fontFamily = FontFamily.Monospace)
                }
            }
        } else {
            Text("2. Paste theirs", style = MaterialTheme.typography.labelLarge)
            OutlinedTextField(
                value = pasted,
                onValueChange = { pasted = it },
                label = { Text("Their link") },
                minLines = 2,
                maxLines = 4,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { context.pastedText()?.let { pasted = it } }) { Text("Paste") }
                Button(onClick = { model.connect(pasted) }, enabled = pasted.isNotBlank()) { Text("Connect") }
            }
        }
        Text("Both phones must be open, and each must paste the other's link within about a minute.")
        model.notice?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        TextButton(onClick = model::endSession) { Text("Cancel") }
    }
}

@Composable
private fun Chat(model: AppModel) {
    var draft by rememberSaveable { mutableStateOf("") }

    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(model.peer?.name.orEmpty(), style = MaterialTheme.typography.titleLarge)
                Text(model.peerFingerprint, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace)
            }
            TextButton(onClick = model::endSession) { Text("Leave") }
        }
        MessageList(model.messages, Modifier.weight(1f))
        model.notice?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(horizontal = 16.dp)) }
        Row(Modifier.fillMaxWidth().padding(12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.Bottom) {
            OutlinedTextField(draft, { draft = it }, modifier = Modifier.weight(1f), placeholder = { Text("Message") }, maxLines = 4)
            Button(
                onClick = {
                    model.send(draft)
                    draft = ""
                },
                enabled = draft.isNotBlank(),
            ) { Text("Send") }
        }
    }
}

private fun Context.copy(text: String) {
    getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("Dolly link", text))
}

private fun Context.pastedText(): String? =
    getSystemService(ClipboardManager::class.java).primaryClip
        ?.takeIf { it.itemCount > 0 }
        ?.getItemAt(0)?.coerceToText(this)?.toString()

private fun Context.share(text: String) {
    startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text), null))
}
