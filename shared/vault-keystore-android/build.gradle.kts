plugins {
    kotlin("multiplatform")
    id("com.android.kotlin.multiplatform.library")
}

kotlin {
    android {
        namespace = "com.alinor.sqrecorder.vault.android"
        compileSdk = 36
        minSdk = 23
        withHostTestBuilder {}
    }

    sourceSets {
        androidMain.dependencies {
            implementation(project(":shared:domain"))
        }
        androidHostTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
