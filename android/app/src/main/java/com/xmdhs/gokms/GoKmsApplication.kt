package com.xmdhs.gokms

import android.app.Application
import com.google.android.material.color.DynamicColors

/**
 * View 体系不会自动应用 Material You 动态配色，
 * 必须在 Activity 创建前注册主题覆盖；Android 12 以下会自动跳过。
 */
class GoKmsApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        DynamicColors.applyToActivitiesIfAvailable(this)
    }
}
