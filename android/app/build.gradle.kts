plugins { id("com.android.application") }
android {
 namespace = "com.alinor.sqrecorder"
 compileSdk = 36
 defaultConfig { applicationId = "com.alinor.sqrecorder"; minSdk = 23; targetSdk = 36; versionCode = 1; versionName = "0.1.0" }
 compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
dependencies {
 implementation(project(":shared:domain"))
 implementation(project(":shared:vault-keystore-android"))
 testImplementation("junit:junit:4.13.2")
}
