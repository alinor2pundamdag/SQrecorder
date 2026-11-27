plugins {
    kotlin("multiplatform")
    id("com.android.kotlin.multiplatform.library")
}

kotlin {
    jvm()
    // Native targets compile the shared domain contract; platform shells/adapters remain separate.
    iosArm64()
    iosSimulatorArm64()
    macosArm64()
    watchosDeviceArm64()
    watchosSimulatorArm64()
    mingwX64()
    linuxX64()
    android {
        // The Android-KMP plugin disables host tests unless explicitly enabled.
        withHostTest {}
        namespace = "com.alinor.sqrecorder.domain"
        compileSdk = 36
        minSdk = 23
    }
    sourceSets {
        commonMain {
            dependencies {
            }
        }
        commonTest {
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}
