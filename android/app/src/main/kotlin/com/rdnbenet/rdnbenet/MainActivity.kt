package com.rdnbenet.rdnbenet

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private val CHANNEL = "com.rdnbenet.rdnbenet/native_lib"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            if (call.method == "getNativeLibraryDir") {
                result.success(applicationInfo.nativeLibraryDir)
            } else {
                result.notImplemented()
            }
        }
    }
}
