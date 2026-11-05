package ru.atomicpel.wifi_help

import android.annotation.SuppressLint
import android.app.Activity
import android.net.http.SslError
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowInsets
import android.webkit.HttpAuthHandler
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout

/**
 * Встроенный браузер для веб-интерфейса роутера. Работает внутри процесса
 * приложения, поэтому ходит через ту же локальную сеть, к которой привязан
 * скан. Самоподписанные сертификаты роутеров принимает — это локальная
 * админка. На Android 15+ (edge-to-edge) сами добавляем отступы под
 * системные панели, иначе страница уходит под статус-бар и навигацию.
 */
class WebActivity : Activity() {
    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Не даём системе рисовать контент под панели.
        if (Build.VERSION.SDK_INT >= 30) {
            window.setDecorFitsSystemWindows(true)
        }

        val root = FrameLayout(this)
        val wv = WebView(this)
        root.addView(wv)
        setContentView(root)

        // Подстраховка: явные отступы под системные панели (статус + навигация).
        if (Build.VERSION.SDK_INT >= 30) {
            root.setOnApplyWindowInsetsListener { v, insets ->
                val bars = insets.getInsets(WindowInsets.Type.systemBars())
                v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
                WindowInsets.CONSUMED
            }
        } else {
            @Suppress("DEPRECATION")
            root.systemUiVisibility = View.SYSTEM_UI_FLAG_LAYOUT_STABLE
            root.fitsSystemWindows = true
        }

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
