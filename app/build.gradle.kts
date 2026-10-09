import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Параметры серверов подставляются при сборке (gradle -P или переменные окружения CI).
// В репозитории их нет. Пустое значение = сервер не проверяется.
fun cfg(name: String): String =
    (project.findProperty(name)?.toString() ?: System.getenv(name) ?: "").replace("\"", "")

android {
    namespace = "ru.netstatus.app"
    compileSdk = 36

    val keystoreProperties = Properties()
    val keystorePropertiesFile = rootProject.file("keystore.properties")

    if (keystorePropertiesFile.exists()) {
        keystoreProperties.load(keystorePropertiesFile.inputStream())
    }

    signingConfigs {
        create("release") {
            if (keystorePropertiesFile.exists()) {
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    defaultConfig {
        applicationId = "ru.netstatus.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 17
        versionName = "0.5.5"
        for (n in listOf("OWN_RU_HOST", "OWN_RU_PORT", "OWN_RU_SNI", "OWN_SW_HOST", "OWN_SW_PORT", "OWN_SW_SNI")) {
            buildConfigField("String", n, "\"" + cfg(n) + "\"")
        }
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            isDebuggable = false
            signingConfig = signingConfigs.getByName("release")
        }

        debug {
            isDebuggable = true
            // Отдельный applicationId: диагностический форк ставится рядом
            // с оригиналом и не конфликтует с его подписью.
            applicationIdSuffix = ".diag"
            versionNameSuffix = "-diag"
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.14" }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("androidx.work:work-runtime-ktx:2.9.0")
}
