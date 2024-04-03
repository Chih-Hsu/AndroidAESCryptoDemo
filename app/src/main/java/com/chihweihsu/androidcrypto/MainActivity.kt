package com.chihweihsu.androidcrypto

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.chihweihsu.androidcrypto.domain.CryptoManager
import com.chihweihsu.androidcrypto.ui.theme.AndroidCryptoTheme
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val cryptoManager = CryptoManager()
            AndroidCryptoTheme {
                var messageToEncrypt by remember { mutableStateOf("") }
                var messageToDecrypt by remember { mutableStateOf("") }

                Column(
                    modifier = Modifier.fillMaxSize().padding(32.dp)
                ) {
                    TextField(
                        value = messageToEncrypt,
                        onValueChange = { messageToEncrypt = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("Enter message to encrypt") }
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Row {
                        Button(onClick = {
                            val message = messageToEncrypt
                            val file = File(filesDir, "secret.txt")
                            if (!file.exists()) {
                                file.createNewFile()
                            }
                            val outputStream = FileOutputStream(file)
                            messageToDecrypt = cryptoManager.encrypt(message, outputStream, this@MainActivity).decodeToString()

                        }) {
                            Text(text = "Encrypt")
                        }
                        Spacer(modifier = Modifier.width(16.dp))
                        Button(onClick = {
                            val file = File(filesDir, "secret.txt")
                            messageToEncrypt = cryptoManager.decrypt(FileInputStream(file), this@MainActivity).decodeToString()

                        }) {
                            Text(text = "Decrypt")
                        }
                    }
                    Text(text = messageToDecrypt)
                }
            }
        }
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    AndroidCryptoTheme {
        Greeting("Android")
    }
}
