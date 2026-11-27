plugins {
    kotlin("multiplatform")
    id("com.android.kotlin.multiplatform.library")
}

kotlin {
    jvm()
    iosArm64()
    iosSimulatorArm64()
    macosArm64()
    watchosDeviceArm64()
    watchosSimulatorArm64()
    mingwX64()
    linuxX64()
    android {
        namespace = "com.alinor.sqrecorder.capability"
        compileSdk = 36
        minSdk = 23
    }
    sourceSets {
        commonMain {
            dependencies {}
        }
        commonTest {
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}
