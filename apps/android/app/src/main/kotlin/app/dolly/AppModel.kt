package app.dolly

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.dolly.core.Contact
import com.dolly.core.Identity
import com.dolly.core.Message
import java.security.SecureRandom
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** Everything the screens show and do. Lives as long as the process, so a session survives rotation. */
class AppModel(private val context: Context) {
    sealed interface Phase {
        data object Idle : Phase
        data object Preparing : Phase
        data object Ready : Phase       // our link is made, waiting for the peer's
        data object Connecting : Phase
        data object Connected : Phase
        class Ended(val reason: String) : Phase
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    var phase by mutableStateOf<Phase>(Phase.Idle)
        private set
    var contacts by mutableStateOf<List<Contact>>(emptyList())
        private set
    var messages by mutableStateOf<List<Message>>(emptyList())
        private set
    var peer by mutableStateOf<Contact?>(null)
        private set
    var expecting by mutableStateOf<Contact?>(null)
        private set
    var peerFingerprint by mutableStateOf("")
        private set
    var myTicket by mutableStateOf("")
        private set
    var myFingerprint by mutableStateOf("")
        private set
    var networkWarning by mutableStateOf<String?>(null)
        private set
    var notice by mutableStateOf<String?>(null)

    private var database: Database? = null
    private var identity: Identity? = null
    private var link: Link? = null
    private var peerKey: ByteArray? = null

    fun start() {
        scope.launch {
            try {
                val database = Database.open(context)
                val identity = database.identity()
                myFingerprint = Fingerprint.of(identity.signing.publicKey)
                contacts = database.contacts()
                this@AppModel.identity = identity
                this@AppModel.database = database
            } catch (e: Exception) {
                notice = "Could not open your encrypted storage: ${e.message}"
            }
        }
    }

    // Sessions

    /** Starts a session. With [contact], only that person's link is accepted. */
    fun beginPairing(contact: Contact?) {
        val identity = identity ?: return
        if (phase != Phase.Idle) return
        phase = Phase.Preparing
        expecting = contact
        scope.launch {
            val link = try {
                Link.open(identity)
            } catch (e: LinkException) {
                phase = Phase.Ended(e.message.orEmpty())
                return@launch
            }
            if (phase != Phase.Preparing) return@launch link.stop()
            this@AppModel.link = link
            myTicket = link.ticketText
            networkWarning = link.warning
            phase = Phase.Ready
            SessionService.start(context)
            for (event in link.events) handle(event)
        }
    }

    fun connect(pasted: String) {
        val link = link
        if (phase != Phase.Ready || link == null) return
        try {
            val key = link.connect(pasted, expecting?.identityKey)
            peerKey = key
            peerFingerprint = Fingerprint.of(key)
            notice = null
            phase = Phase.Connecting
        } catch (e: LinkException) {
            notice = e.message
        }
    }

    fun send(draft: String) {
        val text = draft.trim()
        val peer = peer
        val link = link
        if (phase != Phase.Connected || peer == null || link == null || text.isEmpty()) return
        if (text.toByteArray().size > MAX_TEXT_BYTES) {
            notice = "That message is too long."
            return
        }
        val message = Message(randomId(), System.currentTimeMillis(), outgoing = true, text = text)
        link.send(text)
        messages += message
        store(message, peer)
    }

    fun endSession() {
        link?.stop()
        link = null
        SessionService.stop(context)
        phase = Phase.Idle
        peer = null
        peerKey = null
        expecting = null
        messages = emptyList()
        myTicket = ""
        networkWarning = null
        notice = null
    }

    // Contacts

    fun update(contact: Contact) {
        scope.launch {
            try {
                database?.save(contact)
                contacts = contacts.map { if (it.identityKey.contentEquals(contact.identityKey)) contact else it }
                if (peer?.identityKey?.contentEquals(contact.identityKey) == true) peer = contact
            } catch (e: Exception) {
                notice = "Could not save the change: ${e.message}"
            }
        }
    }

    suspend fun history(contact: Contact): List<Message> =
        runCatching { database?.messages(contact.identityKey) }.getOrNull().orEmpty()

    // Internals

    private suspend fun handle(event: LinkEvent) {
        val database = database ?: return
        when (event) {
            LinkEvent.Connected -> {
                val key = peerKey ?: return
                try {
                    peer = contactFor(key, database)
                    messages = database.messages(key)
                    phase = Phase.Connected
                } catch (e: Exception) {
                    notice = "Could not open the conversation: ${e.message}"
                    link?.stop()
                }
            }
            is LinkEvent.Received -> {
                val peer = peer ?: return
                val message = Message(randomId(), System.currentTimeMillis(), outgoing = false, text = event.text)
                messages += message
                store(message, peer)
            }
            is LinkEvent.Ended -> {
                SessionService.stop(context)
                phase = Phase.Ended(event.reason.explanation)
            }
        }
    }

    /** The saved contact for this key, or a new one if we have never met. */
    private suspend fun contactFor(key: ByteArray, database: Database): Contact {
        contacts.firstOrNull { it.identityKey.contentEquals(key) }?.let { return it }
        val created = Contact(key, "Contact " + Fingerprint.of(key).take(9), addedAt = System.currentTimeMillis())
        database.save(created)
        contacts += created
        return created
    }

    private fun store(message: Message, contact: Contact) {
        scope.launch {
            try {
                database?.append(message, contact.identityKey)
            } catch (e: Exception) {
                notice = "This message could not be saved: ${e.message}"
            }
        }
    }

    private companion object {
        const val MAX_TEXT_BYTES = 16 * 1024
        val random = SecureRandom()

        fun randomId() = ByteArray(16).also(random::nextBytes)
    }
}
