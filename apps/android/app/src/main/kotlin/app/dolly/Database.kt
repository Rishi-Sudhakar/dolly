package app.dolly

import android.content.Context
import com.dolly.core.Contact
import com.dolly.core.Identity
import com.dolly.core.Message
import com.dolly.core.Store
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.withContext

/** The encrypted [Store] behind one serial dispatcher: the store is not thread-safe, and disk stays off the main thread. */
@OptIn(ExperimentalCoroutinesApi::class)
class Database private constructor(private val store: Store) {
    private val serial = Dispatchers.IO.limitedParallelism(1)

    private suspend fun <T> io(block: () -> T): T = withContext(serial) { block() }

    suspend fun identity(): Identity = io { store.identity() }
    suspend fun contacts(): List<Contact> = io { store.contacts() }
    suspend fun save(contact: Contact) = io { store.save(contact) }
    suspend fun append(message: Message, contact: ByteArray) = io { store.append(message, contact) }
    suspend fun messages(contact: ByteArray): List<Message> = io { store.messages(contact) }

    companion object {
        suspend fun open(context: Context): Database = withContext(Dispatchers.IO) {
            Database(Store(File(context.filesDir, "vault"), KeyVault.masterKey(context)))
        }
    }
}
