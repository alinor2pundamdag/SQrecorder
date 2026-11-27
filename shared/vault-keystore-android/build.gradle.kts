plugins {
    kotlin("multiplatform")
    id("com.android.kotlin.multiplatform.library")
}

kotlin {
    android {
        namespace = "com.alinor.sqrecorder.vault.android"
        compileSdk = 36
        minSdk = 23
        withHostTest {}
    }

    sourceSets {
        androidMain.dependencies {
            implementation(project(":shared:domain"))
        }
        getByName("androidHostTest").dependencies {
            implementation(kotlin("test"))
        }
    }
}
