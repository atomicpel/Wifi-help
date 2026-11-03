package ru.atomicpel.wifi_help

import android.annotation.SuppressLint
import android.app.Activity
import android.net.http.SslError
import android.os.Bundle
import android.webkit.HttpAuthHandler
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient

/**
 * Встроенный браузер для веб-интерфейса роутера. Работает внутри процесса
 * приложения, поэтому ходит через ту же локальную сеть, к которой привязан скан
 * (системный браузер может уйти в мобильный интернет). Самоподписанные
 * сертификаты роутеров принимает — это локальная админка.
 */
class WebActivity : Activity() {
    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val wv = WebView(this)
        wv.fitsSystemWindows = true
        setContentView(wv)
        val s = wv.settings
        s.javaScriptEnabled = true
        s.domStorageEnabled = true
        s.builtInZoomControls = true
        s.displayZoomControls = false
        s.useWideViewPort = true
        s.loadWithOverviewMode = true
        val user = intent.getStringExtra("user")
        val pass = intent.getStringExtra("pass")
        wv.webViewClient = object : WebViewClient() {
            override fun onReceivedHttpAuthRequest(view: WebView?, handler: HttpAuthHandler?, host: String?, realm: String?) {
                if (user != null && pass != null) handler?.proceed(user, pass) else handler?.cancel()
            }

            @SuppressLint("WebViewClientOnReceivedSslError")
            override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
                handler?.proceed()
            }
        }
        title = intent.getStringExtra("title") ?: "Роутер"
        wv.loadUrl(intent.getStringExtra("url") ?: "about:blank")
    }
}
